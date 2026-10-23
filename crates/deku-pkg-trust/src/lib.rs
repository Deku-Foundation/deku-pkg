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
    InvalidUrl { field: &'static str, reason: String },
    UnsafeBaseUrl { field: &'static str, reason: &'static str },
    InvalidTrustedRootPath,
    TrustedRootTooLarge { size: u64, limit: u64 },
    DatastoreUnavailable(String),
    InvalidTargetName(String),
    TargetNotFound(String),
    Io { operation: &'static str, message: String },
    Tuf(String),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl { field, reason } => write!(f, "{field} is invalid: {reason}"),
            Self::UnsafeBaseUrl { field, reason } => write!(f, "{field} is unsafe: {reason}"),
            Self::InvalidTrustedRootPath => write!(f, "trusted root metadata must be a regular, non-symlink file"),
            Self::TrustedRootTooLarge { size, limit } => {
                write!(f, "trusted root metadata is {size} bytes; limit is {limit}")
            }
            Self::DatastoreUnavailable(reason) => write!(f, "TUF datastore is not usable: {reason}"),
            Self::InvalidTargetName(name) => write!(f, "target name is not a safe relative path: {name}"),
            Self::TargetNotFound(name) => write!(f, "trusted repository does not contain target: {name}"),
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
        let root_metadata = tokio::fs::symlink_metadata(&self.trusted_root_path)
            .await
            .map_err(|error| TrustError::Io {
                operation: "inspect trusted root metadata",
                message: error.to_string(),
            })?;
        if !root_metadata.file_type().is_file() || root_metadata.file_type().is_symlink() {
            return Err(TrustError::InvalidTrustedRootPath);
        }
        if root_metadata.len() == 0 || root_metadata.len() > MAX_TRUSTED_ROOT_BYTES {
            return Err(TrustError::TrustedRootTooLarge {
                size: root_metadata.len(),
                limit: MAX_TRUSTED_ROOT_BYTES,
            });
        }
        let trusted_root = tokio::fs::read(&self.trusted_root_path)
            .await
            .map_err(|error| TrustError::Io {
                operation: "read trusted root metadata",
                message: error.to_string(),
            })?;

        let datastore_metadata = tokio::fs::symlink_metadata(&self.datastore_path)
            .await
            .map_err(|error| TrustError::DatastoreUnavailable(error.to_string()))?;
        if !datastore_metadata.file_type().is_dir() || datastore_metadata.file_type().is_symlink() {
            return Err(TrustError::DatastoreUnavailable(
                "path must be an existing non-symlink directory".into(),
            ));
        }
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
        let canonical_output = tokio::fs::canonicalize(output_directory)
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
        assert!(parse_https_base("metadata_base_url", "https://packages.example.invalid/metadata/").is_ok());
        assert!(parse_https_base("targets_base_url", "https://packages.example.invalid/targets/").is_ok());
    }

    #[test]
    fn rejects_plain_http() {
        let result = parse_https_base("metadata_base_url", "http://packages.example.invalid/metadata/");
        assert!(matches!(result, Err(TrustError::UnsafeBaseUrl { .. })));
    }

    #[test]
    fn rejects_embedded_credentials() {
        let result = parse_https_base("metadata_base_url", "https://user:pass@packages.example.invalid/metadata/");
        assert!(matches!(result, Err(TrustError::UnsafeBaseUrl { .. })));
    }

    #[test]
    fn rejects_query_and_fragment() {
        assert!(parse_https_base("metadata_base_url", "https://packages.example.invalid/metadata/?token=x").is_err());
        assert!(parse_https_base("metadata_base_url", "https://packages.example.invalid/metadata/#latest").is_err());
    }

    #[test]
    fn requires_directory_style_base_urls() {
        let result = parse_https_base("metadata_base_url", "https://packages.example.invalid/metadata");
        assert!(matches!(result, Err(TrustError::UnsafeBaseUrl { .. })));
    }

    #[test]
    fn rejects_traversal_and_absolute_target_paths() {
        for name in ["", "../escape.rpm", "packages/../escape.rpm", "/absolute/path.rpm", "a//b.rpm", "a/./b.rpm", r"a\b.rpm"] {
            assert!(matches!(validate_target_name(name), Err(TrustError::InvalidTargetName(_))), "accepted unsafe target {name:?}");
        }
    }

    #[test]
    fn accepts_simple_and_nested_relative_target_names() {
        assert!(validate_target_name("hello-1.0.x86_64.rpm").is_ok());
        assert!(validate_target_name("packages/hello-1.0.x86_64.rpm").is_ok());
    }
}
