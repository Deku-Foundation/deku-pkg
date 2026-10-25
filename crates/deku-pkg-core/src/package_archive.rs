//! Native deterministic Deku package archive format, version 1.
//!
//! Format: 8-byte magic, big-endian u32 manifest length, big-endian u64 payload
//! length, JSON manifest, then regular-file bytes in manifest path order.
//! Version 1 deliberately excludes symlinks, device nodes, hard links, and
//! package-controlled scripts. This module only encodes and verifies archives;
//! it never writes to the host filesystem or executes package content.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

const MAGIC: &[u8; 8] = b"DEKUPK01";
const HEADER_LEN: u64 = 20;
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const MAX_PACKAGE_FILES: usize = 100_000;
const MAX_PACKAGE_DEPENDENCIES: usize = 256;
const MAX_PACKAGE_PATH_BYTES: usize = 4_096;
const MAX_PATH_COMPONENT_BYTES: usize = 255;
const MAX_PACKAGE_ARCHIVE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// Canonical package identity stored inside a native archive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub architecture: String,
    /// Deku ABI/profile identifier, not a host architecture alias.
    pub abi: String,
    /// SPDX-compatible expression. Legal approval is a separate release gate.
    pub license: String,
    /// Package names required at runtime, in strictly sorted order.
    pub dependencies: Vec<String>,
}

/// Filesystem object types supported by native archive version 1.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PackageFileKind {
    File,
    Directory,
}

/// Authenticated metadata for one payload path.
///
/// Regular-file digests authenticate the file bytes against this manifest.
/// Repository publisher authentication must be established separately by the
/// signed repository metadata layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    pub path: String,
    pub kind: PackageFileKind,
    /// Unix permission bits only; privileged mode bits are forbidden.
    pub mode: u32,
    /// Regular-file byte length. Directories must have size zero.
    pub size: u64,
    /// Lowercase SHA-256 for regular files, absent for directories.
    pub sha256: Option<String>,
}

/// Input used to produce an archive. Directory content must be empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInputEntry {
    pub path: String,
    pub kind: PackageFileKind,
    pub mode: u32,
    pub content: Vec<u8>,
}

/// Validated manifest for an archive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageArchiveManifest {
    pub schema_version: u32,
    pub package: PackageInfo,
    /// Entries must be in strictly increasing UTF-8 path order.
    pub files: Vec<PackageFile>,
}

/// Result of streaming validation. Payload bytes are not retained in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedArchive {
    pub manifest: PackageArchiveManifest,
    pub archive_size: u64,
    pub payload_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    InvalidMagic,
    UnsupportedSchema,
    ManifestTooLarge { size: usize, limit: usize },
    ArchiveTooLarge { size: u64, limit: u64 },
    InvalidJson(String),
    InvalidPackageName(String),
    InvalidVersion(String),
    UnsupportedArchitecture(String),
    InvalidAbi,
    InvalidLicense,
    InvalidDependency(String),
    TooManyDependencies { count: usize, limit: usize },
    TooManyFiles { count: usize, limit: usize },
    InvalidPath(String),
    InvalidMode { path: String, mode: u32 },
    DuplicatePath(String),
    UnsortedEntries,
    PathTypeConflict(String),
    InvalidEntry(String),
    InvalidDigest(String),
    PayloadLengthMismatch { declared: u64, computed: u64 },
    ArchiveLengthMismatch { declared: u64, actual: u64 },
    DigestMismatch { path: String, expected: String, actual: String },
    LengthOverflow,
    ReadError(String),
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ArchiveError {}

fn digest_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_abi(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-:".contains(&byte))
}

fn valid_license(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > MAX_PACKAGE_PATH_BYTES
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return false;
    }

    value.split('/').all(|component| {
        !component.is_empty()
            && component != "."
            && component != ".."
            && component.len() <= MAX_PATH_COMPONENT_BYTES
    })
}

fn validate_package_info(package: &PackageInfo) -> Result<(), ArchiveError> {
    if !super::valid_name(&package.name) {
        return Err(ArchiveError::InvalidPackageName(package.name.clone()));
    }
    if !super::valid_version(&package.version) {
        return Err(ArchiveError::InvalidVersion(package.version.clone()));
    }
    if !matches!(
        package.architecture.as_str(),
        "x86_64" | "aarch64" | "noarch"
    ) {
        return Err(ArchiveError::UnsupportedArchitecture(
            package.architecture.clone(),
        ));
    }
    if !valid_abi(&package.abi) {
        return Err(ArchiveError::InvalidAbi);
    }
    if !valid_license(&package.license) {
        return Err(ArchiveError::InvalidLicense);
    }
    if package.dependencies.len() > MAX_PACKAGE_DEPENDENCIES {
        return Err(ArchiveError::TooManyDependencies {
            count: package.dependencies.len(),
            limit: MAX_PACKAGE_DEPENDENCIES,
        });
    }

    let mut previous: Option<&str> = None;
    for dependency in &package.dependencies {
        if !super::valid_name(dependency) || dependency == &package.name {
            return Err(ArchiveError::InvalidDependency(dependency.clone()));
        }
        if previous.is_some_and(|prev| prev >= dependency.as_str()) {
            return Err(ArchiveError::InvalidDependency(dependency.clone()));
        }
        previous = Some(dependency);
    }
    Ok(())
}

impl PackageArchiveManifest {
    /// Validate canonical metadata and return the expected payload byte count.
    pub fn validate(&self) -> Result<u64, ArchiveError> {
        if self.schema_version != 1 {
            return Err(ArchiveError::UnsupportedSchema);
        }
        validate_package_info(&self.package)?;

        if self.files.len() > MAX_PACKAGE_FILES {
            return Err(ArchiveError::TooManyFiles {
                count: self.files.len(),
                limit: MAX_PACKAGE_FILES,
            });
        }

        let mut kinds = BTreeMap::<&str, PackageFileKind>::new();
        let mut previous: Option<&str> = None;
        let mut payload_size = 0_u64;

        for entry in &self.files {
            if !valid_path(&entry.path) {
                return Err(ArchiveError::InvalidPath(entry.path.clone()));
            }
            if let Some(prev) = previous {
                if prev == entry.path {
                    return Err(ArchiveError::DuplicatePath(entry.path.clone()));
                }
                if prev > entry.path.as_str() {
                    return Err(ArchiveError::UnsortedEntries);
                }
            }
            previous = Some(&entry.path);

            if entry.mode & !0o777 != 0 {
                return Err(ArchiveError::InvalidMode {
                    path: entry.path.clone(),
                    mode: entry.mode,
                });
            }
            if kinds.insert(entry.path.as_str(), entry.kind).is_some() {
                return Err(ArchiveError::DuplicatePath(entry.path.clone()));
            }

            match entry.kind {
                PackageFileKind::Directory => {
                    if entry.size != 0 || entry.sha256.is_some() {
                        return Err(ArchiveError::InvalidEntry(entry.path.clone()));
                    }
                }
                PackageFileKind::File => {
                    let digest = entry
                        .sha256
                        .as_deref()
                        .ok_or_else(|| ArchiveError::InvalidDigest(entry.path.clone()))?;
                    if !super::valid_digest(digest) {
                        return Err(ArchiveError::InvalidDigest(entry.path.clone()));
                    }
                    payload_size = payload_size
                        .checked_add(entry.size)
                        .ok_or(ArchiveError::LengthOverflow)?;
                    if payload_size > MAX_PACKAGE_ARCHIVE_BYTES {
                        return Err(ArchiveError::ArchiveTooLarge {
                            size: payload_size,
                            limit: MAX_PACKAGE_ARCHIVE_BYTES,
                        });
                    }
                }
            }
        }

        // A regular file cannot also be a parent directory of another entry.
        // Check ancestors in O(path depth), not by comparing every pair.
        for entry in &self.files {
            let mut parent = entry.path.as_str();
            while let Some(separator) = parent.rfind('/') {
                parent = &parent[..separator];
                if kinds.get(parent) == Some(&PackageFileKind::File) {
                    return Err(ArchiveError::PathTypeConflict(parent.to_string()));
                }
            }
        }
        Ok(payload_size)
    }
}

/// Produce a deterministic native package archive from already-built payloads.
///
/// Entries and dependency names are canonicalized by sorting. Duplicate or
/// unsafe paths, unsupported object types, excessive sizes, and invalid
/// metadata fail closed. The resulting Vec is bounded by the archive limit;
/// callers handling large build outputs should use a future streaming writer.
pub fn encode_archive(
    mut package: PackageInfo,
    mut entries: Vec<PackageInputEntry>,
) -> Result<Vec<u8>, ArchiveError> {
    if entries.len() > MAX_PACKAGE_FILES {
        return Err(ArchiveError::TooManyFiles {
            count: entries.len(),
            limit: MAX_PACKAGE_FILES,
        });
    }
    package.dependencies.sort();

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let mut files = Vec::with_capacity(entries.len());

    for entry in &entries {
        if entry.kind == PackageFileKind::Directory && !entry.content.is_empty() {
            return Err(ArchiveError::InvalidEntry(entry.path.clone()));
        }
        let (size, sha256) = match entry.kind {
            PackageFileKind::Directory => (0, None),
            PackageFileKind::File => (entry.content.len() as u64, Some(digest_hex(&entry.content))),
        };
        files.push(PackageFile {
            path: entry.path.clone(),
            kind: entry.kind,
            mode: entry.mode,
            size,
            sha256,
        });
    }

    let manifest = PackageArchiveManifest {
        schema_version: 1,
        package,
        files,
    };
    let payload_size = manifest.validate()?;
    let manifest_bytes = serde_json::to_vec(&manifest)
        .map_err(|error| ArchiveError::InvalidJson(error.to_string()))?;

    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ArchiveError::ManifestTooLarge {
            size: manifest_bytes.len(),
            limit: MAX_MANIFEST_BYTES,
        });
    }

    let manifest_len =
        u32::try_from(manifest_bytes.len()).map_err(|_| ArchiveError::LengthOverflow)?;
    let archive_size = HEADER_LEN
        .checked_add(u64::from(manifest_len))
        .and_then(|size| size.checked_add(payload_size))
        .ok_or(ArchiveError::LengthOverflow)?;
    if archive_size > MAX_PACKAGE_ARCHIVE_BYTES {
        return Err(ArchiveError::ArchiveTooLarge {
            size: archive_size,
            limit: MAX_PACKAGE_ARCHIVE_BYTES,
        });
    }
    let capacity = usize::try_from(archive_size).map_err(|_| ArchiveError::LengthOverflow)?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&manifest_len.to_be_bytes());
    output.extend_from_slice(&payload_size.to_be_bytes());
    output.extend_from_slice(&manifest_bytes);

    for entry in entries {
        if entry.kind == PackageFileKind::File {
            output.extend_from_slice(&entry.content);
        }
    }
    debug_assert_eq!(output.len(), capacity);
    Ok(output)
}

/// Read an archive without buffering its payload. All file bytes are verified
/// against the manifest's SHA-256 digests before the manifest is returned.
pub fn inspect_archive<R: Read + Seek>(
    reader: &mut R,
) -> Result<VerifiedArchive, ArchiveError> {
    let actual_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| ArchiveError::ReadError(error.to_string()))?;
    if actual_size > MAX_PACKAGE_ARCHIVE_BYTES {
        return Err(ArchiveError::ArchiveTooLarge {
            size: actual_size,
            limit: MAX_PACKAGE_ARCHIVE_BYTES,
        });
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ArchiveError::ReadError(error.to_string()))?;

    let mut header = [0_u8; HEADER_LEN as usize];
    reader
        .read_exact(&mut header)
        .map_err(|error| ArchiveError::ReadError(error.to_string()))?;
    if &header[..8] != MAGIC {
        return Err(ArchiveError::InvalidMagic);
    }

    let manifest_len = u32::from_be_bytes(
        header[8..12]
            .try_into()
            .map_err(|_| ArchiveError::InvalidMagic)?,
    ) as usize;
    let declared_payload = u64::from_be_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| ArchiveError::InvalidMagic)?,
    );
    if manifest_len == 0 || manifest_len > MAX_MANIFEST_BYTES {
        return Err(ArchiveError::ManifestTooLarge {
            size: manifest_len,
            limit: MAX_MANIFEST_BYTES,
        });
    }

    let declared_total = HEADER_LEN
        .checked_add(manifest_len as u64)
        .and_then(|size| size.checked_add(declared_payload))
        .ok_or(ArchiveError::LengthOverflow)?;
    if declared_total != actual_size {
        return Err(ArchiveError::ArchiveLengthMismatch {
            declared: declared_total,
            actual: actual_size,
        });
    }

    let mut manifest_bytes = vec![0_u8; manifest_len];
    reader
        .read_exact(&mut manifest_bytes)
        .map_err(|error| ArchiveError::ReadError(error.to_string()))?;
    let manifest: PackageArchiveManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| ArchiveError::InvalidJson(error.to_string()))?;
    let computed_payload = manifest.validate()?;
    if computed_payload != declared_payload {
        return Err(ArchiveError::PayloadLengthMismatch {
            declared: declared_payload,
            computed: computed_payload,
        });
    }

    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    for entry in &manifest.files {
        if entry.kind != PackageFileKind::File {
            continue;
        }
        let expected = entry
            .sha256
            .as_deref()
            .ok_or_else(|| ArchiveError::InvalidDigest(entry.path.clone()))?;
        let mut remaining = entry.size;
        let mut hasher = Sha256::new();
        while remaining > 0 {
            let chunk_len = remaining.min(buffer.len() as u64) as usize;
            reader
                .read_exact(&mut buffer[..chunk_len])
                .map_err(|error| ArchiveError::ReadError(error.to_string()))?;
            hasher.update(&buffer[..chunk_len]);
            remaining -= chunk_len as u64;
        }
        let actual = format!("{:x}", hasher.finalize());
        if actual != expected {
            return Err(ArchiveError::DigestMismatch {
                path: entry.path.clone(),
                expected: expected.to_string(),
                actual,
            });
        }
    }

    Ok(VerifiedArchive {
        manifest,
        archive_size: actual_size,
        payload_size: declared_payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn package() -> PackageInfo {
        PackageInfo {
            name: "hello-deku".to_string(),
            version: "1.2.3-1".to_string(),
            architecture: "x86_64".to_string(),
            abi: "deku1-linux-gnu".to_string(),
            license: "MIT".to_string(),
            dependencies: vec!["libc".to_string(), "zlib".to_string()],
        }
    }

    fn inputs() -> Vec<PackageInputEntry> {
        vec![
            PackageInputEntry {
                path: "usr/bin/hello-deku".to_string(),
                kind: PackageFileKind::File,
                mode: 0o755,
                content: b"#!/bin/sh\nprintf 'hello from deku\\n'\n".to_vec(),
            },
            PackageInputEntry {
                path: "usr/bin".to_string(),
                kind: PackageFileKind::Directory,
                mode: 0o755,
                content: Vec::new(),
            },
            PackageInputEntry {
                path: "usr/share/doc/hello-deku/README".to_string(),
                kind: PackageFileKind::File,
                mode: 0o644,
                content: b"Deku package fixture\n".to_vec(),
            },
        ]
    }

    #[test]
    fn encoded_archive_is_deterministic_and_stream_verified() {
        let first = encode_archive(package(), inputs()).expect("encode first archive");
        let second = encode_archive(package(), inputs()).expect("encode second archive");
        assert_eq!(first, second);

        let verified = inspect_archive(&mut Cursor::new(first.clone())).expect("verify archive");
        assert_eq!(verified.archive_size as usize, first.len());
        assert_eq!(
            verified.payload_size,
            b"#!/bin/sh\nprintf 'hello from deku\\n'\n".len() as u64
                + b"Deku package fixture\n".len() as u64
        );
        assert_eq!(verified.manifest.package.name, "hello-deku");
        assert_eq!(
            verified.manifest.package.dependencies,
            vec!["libc".to_string(), "zlib".to_string()]
        );
        assert_eq!(
            verified
                .manifest
                .files
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "usr/bin",
                "usr/bin/hello-deku",
                "usr/share/doc/hello-deku/README"
            ]
        );
    }

    #[test]
    fn rejects_parent_traversal() {
        let mut entries = inputs();
        entries.push(PackageInputEntry {
            path: "usr/../etc/passwd".to_string(),
            kind: PackageFileKind::File,
            mode: 0o644,
            content: b"not allowed".to_vec(),
        });
        assert!(matches!(
            encode_archive(package(), entries),
            Err(ArchiveError::InvalidPath(_))
        ));
    }

    #[test]
    fn rejects_absolute_and_backslash_paths() {
        for path in ["/etc/passwd", "usr\\bin\\bad", "usr//bin/bad", "usr/./bad"] {
            let result = encode_archive(
                package(),
                vec![PackageInputEntry {
                    path: path.to_string(),
                    kind: PackageFileKind::File,
                    mode: 0o644,
                    content: Vec::new(),
                }],
            );
            assert!(matches!(result, Err(ArchiveError::InvalidPath(_))), "{path}");
        }
    }

    #[test]
    fn rejects_a_file_used_as_a_parent_directory() {
        let entries = vec![
            PackageInputEntry {
                path: "usr".to_string(),
                kind: PackageFileKind::File,
                mode: 0o644,
                content: b"not a directory".to_vec(),
            },
            PackageInputEntry {
                path: "usr/bin/tool".to_string(),
                kind: PackageFileKind::File,
                mode: 0o755,
                content: b"tool".to_vec(),
            },
        ];
        assert!(matches!(
            encode_archive(package(), entries),
            Err(ArchiveError::PathTypeConflict(_))
        ));
    }

    #[test]
    fn rejects_privileged_mode_bits() {
        let result = encode_archive(
            package(),
            vec![PackageInputEntry {
                path: "usr/bin/tool".to_string(),
                kind: PackageFileKind::File,
                mode: 0o4755,
                content: b"tool".to_vec(),
            }],
        );
        assert!(matches!(result, Err(ArchiveError::InvalidMode { .. })));
    }

    #[test]
    fn detects_payload_tampering() {
        let mut bytes = encode_archive(package(), inputs()).expect("encode");
        let manifest_len =
            u32::from_be_bytes(bytes[8..12].try_into().expect("manifest length")) as usize;
        let payload_start = HEADER_LEN as usize + manifest_len;
        bytes[payload_start] ^= 0x01;
        assert!(matches!(
            inspect_archive(&mut Cursor::new(bytes)),
            Err(ArchiveError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = encode_archive(package(), inputs()).expect("encode");
        bytes.push(0);
        assert!(matches!(
            inspect_archive(&mut Cursor::new(bytes)),
            Err(ArchiveError::ArchiveLengthMismatch { .. })
        ));
    }

    #[test]
    fn detects_declared_payload_length_mismatch() {
        let mut bytes = encode_archive(package(), inputs()).expect("encode");
        let current = u64::from_be_bytes(bytes[12..20].try_into().expect("payload length"));
        bytes[12..20].copy_from_slice(&(current + 1).to_be_bytes());
        assert!(matches!(
            inspect_archive(&mut Cursor::new(bytes)),
            Err(ArchiveError::ArchiveLengthMismatch { .. })
        ));
    }

    #[test]
    fn accepts_empty_regular_files_and_directories() {
        let bytes = encode_archive(
            package(),
            vec![
                PackageInputEntry {
                    path: "etc/deku".to_string(),
                    kind: PackageFileKind::Directory,
                    mode: 0o755,
                    content: Vec::new(),
                },
                PackageInputEntry {
                    path: "etc/deku/empty.conf".to_string(),
                    kind: PackageFileKind::File,
                    mode: 0o644,
                    content: Vec::new(),
                },
            ],
        )
        .expect("encode empty file");
        let verified =
            inspect_archive(&mut Cursor::new(bytes)).expect("verify empty file archive");
        assert_eq!(verified.payload_size, 0);
        assert_eq!(verified.manifest.files.len(), 2);
    }

    #[test]
    fn rejects_payload_on_directory_input() {
        let result = encode_archive(
            package(),
            vec![PackageInputEntry {
                path: "usr/share/deku".to_string(),
                kind: PackageFileKind::Directory,
                mode: 0o755,
                content: b"directory has no payload".to_vec(),
            }],
        );
        assert!(matches!(result, Err(ArchiveError::InvalidEntry(_))));
    }

    #[test]
    fn rejects_unsorted_dependencies_after_manifest_validation() {
        let mut info = package();
        info.dependencies = vec!["zlib".to_string(), "libc".to_string()];
        let manifest = PackageArchiveManifest {
            schema_version: 1,
            package: info,
            files: Vec::new(),
        };
        assert!(matches!(
            manifest.validate(),
            Err(ArchiveError::InvalidDependency(_))
        ));
    }
}
