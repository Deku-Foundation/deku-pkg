//! TUF-backed repository trust boundary for Deku's native package manager.
//!
//! This crate deliberately does not define cryptographic formats. It wraps the
//! maintained `tough` implementation of TUF 1.0, requires an out-of-band
//! trusted root metadata file, enforces metadata expiry, persists TUF rollback
//! state, and only publishes a target to the caller after TUF verifies it.
//!
//! It does not install packages or mutate the live operating system.

use std::fmt;
use std::path::{Path, PathBuf};

use tough::{ExpirationEnforcement, Limits, Prefix, Repository, RepositoryLoader, TargetName};
use url::Url;

const MAX_TRUSTED_ROOT_BYTES: u64 = 1024 * 1024;
const MAX_ROOT_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_TARGETS_METADATA_BYTES: u64 = 10 * 1024 * 1024;
const MAX_TIMESTAMP_METADATA_BYTES: u64 = 1024 * 1024;
const MAX_SNAPSHOT_METADATA_BYTES: u64 = 10 * 1024 * 1024;
const MAX_ROOT_UPDATES: u64 = 64;
const MAX_TARGET_NAME_BYTES: usize = 1024;

/// Errors at the package-repository trust boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    InvalidUrl {
        field: &'static str,
        reason: String,
    },
    UnsafeBaseUrl {
        field: &'static str,
        reason: &'static str,
    },
    InvalidTrustedRootPath,
    TrustedRootEmpty,
    TrustedRootTooLarge {
        size: u64,
        limit: u64,
    },
    DatastoreUnavailable(String),
    UnsafeDirectoryPermissions {
        field: &'static str,
    },
    UnsafeDirectoryOwner {
        field: &'static str,
        expected_uid: u32,
        actual_uid: u32,
    },
    UnsafeFilePermissions {
        field: &'static str,
    },
    UnsafeFileOwner {
        field: &'static str,
        expected_uid: u32,
        actual_uid: u32,
    },
    UnsupportedPlatform {
        field: &'static str,
    },
    InvalidTargetName(String),
    TargetNotFound(String),
    TargetTooLarge {
        name: String,
        size: u64,
        limit: u64,
    },
    Io {
        operation: &'static str,
        message: String,
    },
    Tuf(String),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl { field, reason } => write!(f, "{field} is invalid: {reason}"),
            Self::UnsafeBaseUrl { field, reason } => write!(f, "{field} is unsafe: {reason}"),
            Self::InvalidTrustedRootPath => write!(
                f,
                "trusted root metadata must be a regular, non-symlink file"
            ),
            Self::TrustedRootEmpty => write!(f, "trusted root metadata must not be empty"),
            Self::TrustedRootTooLarge { size, limit } => {
                write!(f, "trusted root metadata is {size} bytes; limit is {limit}")
            }
            Self::DatastoreUnavailable(reason) => {
                write!(f, "TUF datastore is not usable: {reason}")
            }
            Self::UnsafeDirectoryPermissions { field } => write!(
                f,
                "{field} must not be group- or world-writable; metadata rollback state must be protected"
            ),
            Self::UnsafeDirectoryOwner {
                field,
                expected_uid,
                actual_uid,
            } => write!(
                f,
                "{field} is owned by UID {actual_uid}; the current effective UID is {expected_uid}"
            ),
            Self::UnsafeFilePermissions { field } => {
                write!(f, "{field} must not be group- or world-writable")
            }
            Self::UnsafeFileOwner {
                field,
                expected_uid,
                actual_uid,
            } => write!(
                f,
                "{field} is owned by UID {actual_uid}; the current effective UID is {expected_uid}"
            ),
            Self::UnsupportedPlatform { field } => write!(
                f,
                "secure ownership and no-follow checks for {field} are not supported on this platform"
            ),
            Self::InvalidTargetName(name) => {
                write!(f, "target name is not a safe relative path: {name}")
            }
            Self::TargetNotFound(name) => {
                write!(f, "trusted repository does not contain target: {name}")
            }
            Self::TargetTooLarge { name, size, limit } => {
                write!(f, "target {name} is {size} bytes; maximum permitted size is {limit}")
            }
            Self::Io { operation, message } => write!(f, "{operation} failed: {message}"),
            Self::Tuf(message) => write!(f, "TUF verification failed: {message}"),
        }
    }
}

impl std::error::Error for TrustError {}

/// Configuration for loading a TUF repository.
///
/// `trusted_root_path` must point to root metadata distributed through an
/// out-of-band trust channel (for example, shipped with a reviewed package
/// manager or operating-system image). Never download this initial root from
/// the same untrusted repository before trust has been established.
///
/// `datastore_path` must be a persistent directory owned by the package
/// manager. It stores the last trusted metadata versions and is necessary to
/// detect rollback attempts across client invocations.
#[derive(Debug, Clone)]
pub struct RepositoryConfig {
    trusted_root_path: PathBuf,
    metadata_base_url: Url,
    targets_base_url: Url,
    datastore_path: PathBuf,
}

impl RepositoryConfig {
    /// Build a configuration, rejecting transport and URL ambiguities early.
    ///
    /// Production repository endpoints must use HTTPS, contain no embedded
    /// credentials/query/fragment, and end with a slash so URL joining cannot
    /// silently replace the final path component.
    pub fn new(
        trusted_root_path: impl Into<PathBuf>,
        metadata_base_url: &str,
        targets_base_url: &str,
        datastore_path: impl Into<PathBuf>,
    ) -> Result<Self, TrustError> {
        let metadata_base_url = parse_https_base("metadata_base_url", metadata_base_url)?;
        let targets_base_url = parse_https_base("targets_base_url", targets_base_url)?;

        Ok(Self {
            trusted_root_path: trusted_root_path.into(),
            metadata_base_url,
            targets_base_url,
            datastore_path: datastore_path.into(),
        })
    }

    /// Load and authenticate metadata using TUF's safe expiration policy.
    ///
    /// The datastore must already exist, must be a real directory rather than
    /// a symlink, and should be writable only by the package-management service.
    pub async fn load(&self) -> Result<TrustedRepository, TrustError> {
        // Open and validate the trust anchor as one bounded operation. A
        // separate symlink_metadata() followed by read() leaves a check/use race.
        let trusted_root_path = self.trusted_root_path.clone();
        let trusted_root =
            tokio::task::spawn_blocking(move || read_trusted_root(&trusted_root_path))
                .await
                .map_err(|error| TrustError::Io {
                    operation: "join trusted root metadata read",
                    message: error.to_string(),
                })??;

        let datastore_metadata = tokio::fs::symlink_metadata(&self.datastore_path)
            .await
            .map_err(|error| TrustError::DatastoreUnavailable(error.to_string()))?;
        if !datastore_metadata.file_type().is_dir() || datastore_metadata.file_type().is_symlink() {
            return Err(TrustError::DatastoreUnavailable(
                "path must be an existing non-symlink directory".into(),
            ));
        }
        ensure_private_directory(&datastore_metadata, "datastore_path")?;
        let datastore = tokio::fs::canonicalize(&self.datastore_path)
            .await
            .map_err(|error| TrustError::DatastoreUnavailable(error.to_string()))?;

        let repository = RepositoryLoader::new(
            &trusted_root,
            self.metadata_base_url.clone(),
            self.targets_base_url.clone(),
        )
        .datastore(datastore)
        .expiration_enforcement(ExpirationEnforcement::Safe)
        .limits(Limits {
            max_root_size: MAX_ROOT_METADATA_BYTES,
            max_targets_size: MAX_TARGETS_METADATA_BYTES,
            max_timestamp_size: MAX_TIMESTAMP_METADATA_BYTES,
            max_snapshot_size: MAX_SNAPSHOT_METADATA_BYTES,
            max_root_updates: MAX_ROOT_UPDATES,
        })
        .load()
        .await
        .map_err(|error| TrustError::Tuf(error.to_string()))?;

        Ok(TrustedRepository { inner: repository })
    }
}

/// Information authenticated by the repository's signed TUF target metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedTargetInfo {
    pub name: String,
    pub length: u64,
    pub sha256: String,
}

/// A repository whose root/targets/snapshot/timestamp metadata was accepted by TUF.
///
/// Loading it verifies metadata signatures, versions and expirations. The
/// persistent TUF datastore also records metadata state to reject rollback.
/// This wrapper does not install packages or authorize privileged operations.
#[derive(Debug, Clone)]
pub struct TrustedRepository {
    inner: Repository,
}

impl TrustedRepository {
    /// Return the number of top-level target entries in the loaded repository.
    ///
    /// The current TUF wrapper deliberately does not enable delegated roles:
    /// the selected `tough` version documents delegated-role support as a
    /// limitation. Deku must explicitly evaluate and test delegation before
    /// relying on it for a large split repository.
    pub fn target_count(&self) -> usize {
        self.inner.all_targets().count()
    }

    /// Read the signed length and SHA-256 for a target before downloading it.
    ///
    /// This allows callers to apply size policy before network/disk I/O and to
    /// ensure that package metadata points to the same digest as signed target
    /// metadata. It does not download target bytes.
    pub fn target_info(&self, target_name: &str) -> Result<TrustedTargetInfo, TrustError> {
        validate_target_name(target_name)?;
        let target = TargetName::new(target_name.to_owned())
            .map_err(|_| TrustError::InvalidTargetName(target_name.to_owned()))?;
        let description = self
            .inner
            .all_targets()
            .find(|(candidate, _)| candidate.resolved() == target.resolved())
            .map(|(_, description)| description)
            .ok_or_else(|| TrustError::TargetNotFound(target_name.to_owned()))?;

        Ok(TrustedTargetInfo {
            name: target_name.to_owned(),
            length: description.length,
            sha256: encode_lower_hex(&description.hashes.sha256),
        })
    }

    /// Download a target into a caller-owned staging directory.
    ///
    /// `tough` streams bytes into a temporary file and persists the file only
    /// after its digest matches signed target metadata. This method never
    /// installs the file or writes to a system root. The destination directory
    /// must exist and must be controlled by the caller.
    pub async fn download_verified_target(
        &self,
        target_name: &str,
        staging_directory: impl AsRef<Path>,
    ) -> Result<PathBuf, TrustError> {
        validate_target_name(target_name)?;
        let target = TargetName::new(target_name.to_owned())
            .map_err(|_| TrustError::InvalidTargetName(target_name.to_owned()))?;

        let found = self
            .inner
            .all_targets()
            .any(|(candidate, _)| candidate.resolved() == target.resolved());
        if !found {
            return Err(TrustError::TargetNotFound(target_name.to_owned()));
        }

        let output_directory = staging_directory.as_ref();
        let output_type = tokio::fs::symlink_metadata(output_directory)
            .await
            .map_err(|error| TrustError::Io {
                operation: "inspect target staging directory",
                message: error.to_string(),
            })?;
        if !output_type.file_type().is_dir() || output_type.file_type().is_symlink() {
            return Err(TrustError::DatastoreUnavailable(
                "target staging path must be an existing non-symlink directory".into(),
            ));
        }
        ensure_private_directory(&output_type, "target staging directory")?;
        let canonical_output =
            tokio::fs::canonicalize(output_directory)
                .await
                .map_err(|error| TrustError::Io {
                    operation: "canonicalize target staging directory",
                    message: error.to_string(),
                })?;

        self.inner
            .save_target(&target, &canonical_output, Prefix::None)
            .await
            .map_err(|error| TrustError::Tuf(error.to_string()))?;

        Ok(canonical_output.join(target.resolved()))
    }
}

/// Open the initial trust anchor without following a final-component symlink,
/// verify the opened file's metadata, and enforce the byte limit while reading.
/// Caller-provided ancestor directories must also be protected from untrusted
/// replacement; O_NOFOLLOW guards the final path component atomically.
#[cfg(unix)]
fn read_trusted_root(path: &Path) -> Result<Vec<u8>, TrustError> {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|error| {
        if error.raw_os_error() == Some(libc::ELOOP) {
            TrustError::InvalidTrustedRootPath
        } else {
            TrustError::Io {
                operation: "open trusted root metadata without following symlinks",
                message: error.to_string(),
            }
        }
    })?;
    let metadata = file.metadata().map_err(|error| TrustError::Io {
        operation: "inspect opened trusted root metadata",
        message: error.to_string(),
    })?;
    if !metadata.is_file() {
        return Err(TrustError::InvalidTrustedRootPath);
    }
    ensure_private_file(&metadata, "trusted_root_path")?;
    if metadata.len() == 0 {
        return Err(TrustError::TrustedRootEmpty);
    }
    if metadata.len() > MAX_TRUSTED_ROOT_BYTES {
        return Err(TrustError::TrustedRootTooLarge {
            size: metadata.len(),
            limit: MAX_TRUSTED_ROOT_BYTES,
        });
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_TRUSTED_ROOT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| TrustError::Io {
            operation: "read trusted root metadata",
            message: error.to_string(),
        })?;
    if bytes.len() as u64 > MAX_TRUSTED_ROOT_BYTES {
        return Err(TrustError::TrustedRootTooLarge {
            size: bytes.len() as u64,
            limit: MAX_TRUSTED_ROOT_BYTES,
        });
    }
    if bytes.is_empty() {
        return Err(TrustError::TrustedRootEmpty);
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_trusted_root(_path: &Path) -> Result<Vec<u8>, TrustError> {
    Err(TrustError::UnsupportedPlatform {
        field: "trusted_root_path",
    })
}

/// The durable TUF datastore contains anti-rollback state. It and the target
/// staging directory must be owned by the effective user running this process
/// and must not be group/world-writable. Ancestor directories must be protected
/// by service installation and deployment policy as well.
#[cfg(unix)]
fn ensure_private_directory(
    metadata: &std::fs::Metadata,
    field: &'static str,
) -> Result<(), TrustError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let expected_uid = effective_uid();
    if metadata.uid() != expected_uid {
        return Err(TrustError::UnsafeDirectoryOwner {
            field,
            expected_uid,
            actual_uid: metadata.uid(),
        });
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(TrustError::UnsafeDirectoryPermissions { field });
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_file(
    metadata: &std::fs::Metadata,
    field: &'static str,
) -> Result<(), TrustError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let expected_uid = effective_uid();
    if metadata.uid() != expected_uid {
        return Err(TrustError::UnsafeFileOwner {
            field,
            expected_uid,
            actual_uid: metadata.uid(),
        });
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(TrustError::UnsafeFilePermissions { field });
    }
    Ok(())
}

#[cfg(unix)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no pointer arguments and has no preconditions; it
    // returns the effective UID of the current process.
    unsafe { libc::geteuid() as u32 }
}

#[cfg(not(unix))]
fn ensure_private_directory(
    _metadata: &std::fs::Metadata,
    field: &'static str,
) -> Result<(), TrustError> {
    Err(TrustError::UnsupportedPlatform { field })
}

fn parse_https_base(field: &'static str, value: &str) -> Result<Url, TrustError> {
    let url = Url::parse(value).map_err(|error| TrustError::InvalidUrl {
        field,
        reason: error.to_string(),
    })?;
    if url.scheme() != "https" {
        return Err(TrustError::UnsafeBaseUrl {
            field,
            reason: "HTTPS is required for production repositories",
        });
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(TrustError::UnsafeBaseUrl {
            field,
            reason: "a hostname is required and embedded credentials are forbidden",
        });
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(TrustError::UnsafeBaseUrl {
            field,
            reason: "query strings and fragments are forbidden",
        });
    }
    if !url.path().ends_with('/') {
        return Err(TrustError::UnsafeBaseUrl {
            field,
            reason: "base URL path must end with '/'",
        });
    }
    Ok(url)
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn validate_target_name(name: &str) -> Result<(), TrustError> {
    let invalid = name.is_empty()
        || name.len() > MAX_TARGET_NAME_BYTES
        || name.starts_with('/')
        || name.contains('\\')
        || name.chars().any(|character| character.is_control())
        || name
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..");

    if invalid {
        return Err(TrustError::InvalidTargetName(name.to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_repository_bases() {
        assert!(
            parse_https_base(
                "metadata_base_url",
                "https://packages.example.invalid/metadata/"
            )
            .is_ok()
        );
        assert!(
            parse_https_base(
                "targets_base_url",
                "https://packages.example.invalid/targets/"
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_plain_http() {
        let result = parse_https_base(
            "metadata_base_url",
            "http://packages.example.invalid/metadata/",
        );
        assert!(matches!(result, Err(TrustError::UnsafeBaseUrl { .. })));
    }

    #[test]
    fn rejects_embedded_credentials() {
        let result = parse_https_base(
            "metadata_base_url",
            "https://user:pass@packages.example.invalid/metadata/",
        );
        assert!(matches!(result, Err(TrustError::UnsafeBaseUrl { .. })));
    }

    #[test]
    fn rejects_query_and_fragment() {
        assert!(
            parse_https_base(
                "metadata_base_url",
                "https://packages.example.invalid/metadata/?token=x"
            )
            .is_err()
        );
        assert!(
            parse_https_base(
                "metadata_base_url",
                "https://packages.example.invalid/metadata/#latest"
            )
            .is_err()
        );
    }

    #[test]
    fn requires_directory_style_base_urls() {
        let result = parse_https_base(
            "metadata_base_url",
            "https://packages.example.invalid/metadata",
        );
        assert!(matches!(result, Err(TrustError::UnsafeBaseUrl { .. })));
    }

    #[test]
    fn rejects_traversal_and_absolute_target_paths() {
        for name in [
            "",
            "../escape.rpm",
            "packages/../escape.rpm",
            "/absolute/path.rpm",
            "a//b.rpm",
            "a/./b.rpm",
            r"a\b.rpm",
        ] {
            assert!(
                matches!(
                    validate_target_name(name),
                    Err(TrustError::InvalidTargetName(_))
                ),
                "accepted unsafe target {name:?}"
            );
        }
    }

    #[test]
    fn accepts_simple_and_nested_relative_target_names() {
        assert!(validate_target_name("hello-1.0.x86_64.rpm").is_ok());
        assert!(validate_target_name("packages/hello-1.0.x86_64.rpm").is_ok());
    }
}

#[cfg(test)]
mod signed_repository_fixture_tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn upstream_fixture() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("tuf-reference-impl")
    }

    fn local_fixture_config(repository_dir: &Path, datastore: &Path) -> RepositoryConfig {
        let metadata_dir = repository_dir.join("metadata");
        let targets_dir = repository_dir.join("targets");
        RepositoryConfig {
            trusted_root_path: metadata_dir.join("1.root.json"),
            metadata_base_url: Url::from_directory_path(metadata_dir)
                .expect("metadata directory should convert to file URL"),
            targets_base_url: Url::from_directory_path(targets_dir)
                .expect("targets directory should convert to file URL"),
            datastore_path: datastore.to_path_buf(),
        }
    }

    fn copy_directory(source: &Path, destination: &Path) -> std::io::Result<()> {
        fs::create_dir_all(destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let from = entry.path();
            let to = destination.join(entry.file_name());
            if file_type.is_dir() {
                copy_directory(&from, &to)?;
            } else if file_type.is_file() {
                fs::copy(from, to)?;
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "fixture contains an unexpected non-file entry",
                ));
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn loads_signed_reference_metadata_and_downloads_a_verified_target() {
        let temporary = tempdir().expect("temporary directory");
        let datastore = temporary.path().join("datastore");
        let staging = temporary.path().join("staging");
        fs::create_dir(&datastore).unwrap();
        fs::create_dir(&staging).unwrap();

        let trusted = local_fixture_config(&upstream_fixture(), &datastore)
            .load()
            .await
            .expect("signed, unexpired reference metadata should load");

        assert!(
            trusted.target_count() >= 2,
            "fixture should expose the two top-level signed targets"
        );
        let target_info = trusted
            .target_info("file1.txt")
            .expect("target should have signed metadata");
        assert_eq!(target_info.length, b"This is an example target file.".len() as u64);
        assert_eq!(target_info.sha256.len(), 64);
        assert!(trusted.target_info("../escape").is_err());

        let downloaded = trusted
            .download_verified_target("file1.txt", &staging)
            .await
            .expect("target bytes matching signed TUF metadata should be saved");
        assert_eq!(
            fs::read_to_string(downloaded).unwrap(),
            "This is an example target file."
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_group_or_world_writable_trusted_root_metadata() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempdir().expect("temporary directory");
        let datastore = temporary.path().join("datastore");
        let root_copy = temporary.path().join("trusted-root.json");
        fs::create_dir(&datastore).unwrap();
        fs::copy(
            upstream_fixture().join("metadata").join("1.root.json"),
            &root_copy,
        )
        .unwrap();
        fs::set_permissions(&root_copy, fs::Permissions::from_mode(0o666)).unwrap();

        let mut config = local_fixture_config(&upstream_fixture(), &datastore);
        config.trusted_root_path = root_copy;
        let result = config.load().await;
        assert!(
            matches!(
                result,
                Err(TrustError::UnsafeFilePermissions {
                    field: "trusted_root_path"
                })
            ),
            "group/world-writable trust anchors must be rejected, got {result:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlinked_trusted_root_metadata() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().expect("temporary directory");
        let datastore = temporary.path().join("datastore");
        let trusted_root_copy = temporary.path().join("trusted-root.json");
        let trusted_root_link = temporary.path().join("trusted-root-link.json");
        fs::create_dir(&datastore).unwrap();
        fs::copy(
            upstream_fixture().join("metadata").join("1.root.json"),
            &trusted_root_copy,
        )
        .unwrap();
        symlink(&trusted_root_copy, &trusted_root_link).unwrap();

        let mut config = local_fixture_config(&upstream_fixture(), &datastore);
        config.trusted_root_path = trusted_root_link;
        let result = config.load().await;
        assert!(
            matches!(result, Err(TrustError::InvalidTrustedRootPath)),
            "trusted root symlinks must be rejected, got {result:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlinked_rollback_datastore() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().expect("temporary directory");
        let real_datastore = temporary.path().join("real-datastore");
        let datastore_link = temporary.path().join("datastore-link");
        fs::create_dir(&real_datastore).unwrap();
        symlink(&real_datastore, &datastore_link).unwrap();

        let result = local_fixture_config(&upstream_fixture(), &datastore_link)
            .load()
            .await;
        assert!(
            matches!(result, Err(TrustError::DatastoreUnavailable(_))),
            "rollback state must not be redirected through a symlink, got {result:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlinked_target_staging_directory() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().expect("temporary directory");
        let datastore = temporary.path().join("datastore");
        let real_staging = temporary.path().join("real-staging");
        let staging_link = temporary.path().join("staging-link");
        fs::create_dir(&datastore).unwrap();
        fs::create_dir(&real_staging).unwrap();
        symlink(&real_staging, &staging_link).unwrap();

        let repository = local_fixture_config(&upstream_fixture(), &datastore)
            .load()
            .await
            .expect("signed local fixture should load");
        let result = repository
            .download_verified_target("file1.txt", &staging_link)
            .await;
        assert!(
            matches!(result, Err(TrustError::DatastoreUnavailable(_))),
            "staging symlinks must be rejected, got {result:?}"
        );
        assert!(!real_staging.join("file1.txt").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_group_or_world_writable_tuf_datastore() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempdir().expect("temporary directory");
        let datastore = temporary.path().join("datastore");
        fs::create_dir(&datastore).unwrap();
        fs::set_permissions(&datastore, fs::Permissions::from_mode(0o777)).unwrap();

        let config = local_fixture_config(&upstream_fixture(), &datastore);
        let result = config.load().await;
        assert!(
            matches!(
                result,
                Err(TrustError::UnsafeDirectoryPermissions {
                    field: "datastore_path"
                })
            ),
            "shared-writable rollback state must be rejected, got {result:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_group_or_world_writable_target_staging_directory() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempdir().expect("temporary directory");
        let datastore = temporary.path().join("datastore");
        let staging = temporary.path().join("staging");
        fs::create_dir(&datastore).unwrap();
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o777)).unwrap();

        let repository = local_fixture_config(&upstream_fixture(), &datastore)
            .load()
            .await
            .expect("signed local fixture should load");
        let result = repository
            .download_verified_target("file1.txt", &staging)
            .await;
        assert!(
            matches!(
                result,
                Err(TrustError::UnsafeDirectoryPermissions {
                    field: "target staging directory"
                })
            ),
            "shared-writable target path must be rejected, got {result:?}"
        );
        assert!(!staging.join("file1.txt").exists());
    }

    #[tokio::test]
    async fn rejects_target_bytes_that_do_not_match_signed_metadata() {
        let temporary = tempdir().expect("temporary directory");
        let repository_copy = temporary.path().join("repository");
        let datastore = temporary.path().join("datastore");
        let staging = temporary.path().join("staging");
        copy_directory(&upstream_fixture(), &repository_copy).unwrap();
        fs::write(
            repository_copy.join("targets").join("file1.txt"),
            b"tampered target bytes",
        )
        .unwrap();
        fs::create_dir(&datastore).unwrap();
        fs::create_dir(&staging).unwrap();

        let trusted = local_fixture_config(&repository_copy, &datastore)
            .load()
            .await
            .expect("metadata remains correctly signed; only target bytes were altered");

        let result = trusted
            .download_verified_target("file1.txt", &staging)
            .await;
        assert!(
            matches!(result, Err(TrustError::Tuf(_))),
            "modified target must fail signed length/digest verification, got {result:?}"
        );
        assert!(
            !staging.join("file1.txt").exists(),
            "an unverified target must not be persisted to the staging destination"
        );
    }
}
