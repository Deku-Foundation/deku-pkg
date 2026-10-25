//! Streaming builder for native Deku package archives.
//!
//! This module turns a reviewed build DESTDIR into a deterministic native
//! archive. It rejects symlinks and special filesystem objects, hashes files
//! before emitting the manifest, then re-hashes them while streaming payload
//! bytes. Callers must write to a temporary output and publish it atomically,
//! because a source mutation detected during the second pass leaves a partial
//! byte stream in the supplied writer.

use crate::package_archive::{
    ArchiveError, MAX_PACKAGE_ARCHIVE_BYTES, PackageArchiveManifest, PackageFile, PackageFileKind,
    PackageInfo,
};
use crate::version::DekuVersion;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"DEKUPK01";
const HEADER_LEN: u64 = 20;
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    Archive(ArchiveError),
    UnsafeSource(String),
    SourceChanged(String),
    Io {
        operation: &'static str,
        path: String,
        message: String,
    },
    Write(String),
}

impl std::fmt::Display for BuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for BuilderError {}

impl From<ArchiveError> for BuilderError {
    fn from(value: ArchiveError) -> Self {
        Self::Archive(value)
    }
}

#[derive(Debug, Clone)]
struct SourceEntry {
    physical_path: PathBuf,
    metadata: PackageFile,
}

/// Build and stream a native archive from a DESTDIR.
///
/// The input root must already exist and be a real directory. Only regular
/// files and directories are permitted. All files are bounded by the archive
/// size limit and are read twice to detect changes during packaging.
pub fn write_archive_from_directory<W: Write>(
    source_root: impl AsRef<Path>,
    mut package: PackageInfo,
    writer: &mut W,
) -> Result<u64, BuilderError> {
    let root = source_root.as_ref();
    let root_metadata = fs::symlink_metadata(root).map_err(|error| BuilderError::Io {
        operation: "inspect package source root",
        path: root.display().to_string(),
        message: error.to_string(),
    })?;
    if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
        return Err(BuilderError::UnsafeSource(root.display().to_string()));
    }
    if directory_is_group_or_world_writable(&root_metadata) {
        return Err(BuilderError::UnsafeSource(root.display().to_string()));
    }

    let parsed_version = DekuVersion::parse(&package.version)
        .map_err(|_| BuilderError::Archive(ArchiveError::InvalidVersion(package.name.clone())))?;
    package.version = parsed_version.canonical();
    package.dependencies.sort();

    let mut entries = Vec::<SourceEntry>::new();
    let mut total_payload = 0_u64;
    collect_entries(root, root, &mut entries, &mut total_payload)?;
    entries.sort_by(|left, right| left.metadata.path.cmp(&right.metadata.path));

    let manifest = PackageArchiveManifest {
        schema_version: 1,
        package,
        files: entries.iter().map(|entry| entry.metadata.clone()).collect(),
    };
    let validated_payload = manifest.validate()?;
    if validated_payload != total_payload {
        return Err(BuilderError::SourceChanged(
            "source file sizes changed while constructing manifest".to_string(),
        ));
    }
    let manifest_bytes =
        serde_json::to_vec(&manifest).map_err(|error| BuilderError::Write(error.to_string()))?;
    if manifest_bytes.is_empty() || manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(BuilderError::Archive(ArchiveError::ManifestTooLarge {
            size: manifest_bytes.len(),
            limit: MAX_MANIFEST_BYTES,
        }));
    }

    let manifest_len = u32::try_from(manifest_bytes.len())
        .map_err(|_| BuilderError::Archive(ArchiveError::LengthOverflow))?;
    let archive_size = HEADER_LEN
        .checked_add(u64::from(manifest_len))
        .and_then(|size| size.checked_add(total_payload))
        .ok_or(BuilderError::Archive(ArchiveError::LengthOverflow))?;
    if archive_size > MAX_PACKAGE_ARCHIVE_BYTES {
        return Err(BuilderError::Archive(ArchiveError::ArchiveTooLarge {
            size: archive_size,
            limit: MAX_PACKAGE_ARCHIVE_BYTES,
        }));
    }

    writer
        .write_all(MAGIC)
        .and_then(|()| writer.write_all(&manifest_len.to_be_bytes()))
        .and_then(|()| writer.write_all(&total_payload.to_be_bytes()))
        .and_then(|()| writer.write_all(&manifest_bytes))
        .map_err(|error| BuilderError::Write(error.to_string()))?;

    for entry in &entries {
        if entry.metadata.kind == PackageFileKind::File {
            copy_verified_payload(entry, writer)?;
        }
    }

    Ok(archive_size)
}

fn collect_entries(
    root: &Path,
    directory: &Path,
    entries: &mut Vec<SourceEntry>,
    total_payload: &mut u64,
) -> Result<(), BuilderError> {
    let iterator = fs::read_dir(directory).map_err(|error| BuilderError::Io {
        operation: "list package source directory",
        path: directory.display().to_string(),
        message: error.to_string(),
    })?;

    for child in iterator {
        let child = child.map_err(|error| BuilderError::Io {
            operation: "read package source directory entry",
            path: directory.display().to_string(),
            message: error.to_string(),
        })?;
        let physical_path = child.path();
        let fs_metadata =
            fs::symlink_metadata(&physical_path).map_err(|error| BuilderError::Io {
                operation: "inspect package source entry",
                path: physical_path.display().to_string(),
                message: error.to_string(),
            })?;

        if fs_metadata.file_type().is_symlink()
            || (!fs_metadata.file_type().is_file() && !fs_metadata.file_type().is_dir())
        {
            return Err(BuilderError::UnsafeSource(
                physical_path.display().to_string(),
            ));
        }

        let relative = physical_path
            .strip_prefix(root)
            .map_err(|_| BuilderError::UnsafeSource(physical_path.display().to_string()))?;
        let path = relative
            .to_str()
            .ok_or_else(|| {
                BuilderError::Archive(ArchiveError::InvalidPath(
                    "package path is not valid UTF-8".to_string(),
                ))
            })?
            .replace(std::path::MAIN_SEPARATOR, "/");

        let kind = if fs_metadata.file_type().is_dir() {
            PackageFileKind::Directory
        } else {
            PackageFileKind::File
        };
        let mode = source_mode(&fs_metadata, kind);
        if mode & !0o777 != 0 || mode & 0o022 != 0 {
            return Err(BuilderError::Archive(ArchiveError::InvalidMode {
                path: path.clone(),
                mode,
            }));
        }
        let (size, sha256) = match kind {
            PackageFileKind::Directory => (0, None),
            PackageFileKind::File => {
                let size = fs_metadata.len();
                *total_payload = total_payload
                    .checked_add(size)
                    .ok_or(BuilderError::Archive(ArchiveError::LengthOverflow))?;
                if *total_payload > MAX_PACKAGE_ARCHIVE_BYTES {
                    return Err(BuilderError::Archive(ArchiveError::ArchiveTooLarge {
                        size: *total_payload,
                        limit: MAX_PACKAGE_ARCHIVE_BYTES,
                    }));
                }
                (size, Some(hash_source_file(&physical_path, size, &path)?))
            }
        };

        entries.push(SourceEntry {
            physical_path: physical_path.clone(),
            metadata: PackageFile {
                path,
                kind,
                mode,
                size,
                sha256,
            },
        });

        if kind == PackageFileKind::Directory {
            collect_entries(root, &physical_path, entries, total_payload)?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn directory_is_group_or_world_writable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o022 != 0
}

#[cfg(not(unix))]
fn directory_is_group_or_world_writable(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn source_mode(metadata: &fs::Metadata, _kind: PackageFileKind) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn source_mode(_metadata: &fs::Metadata, kind: PackageFileKind) -> u32 {
    match kind {
        PackageFileKind::Directory => 0o755,
        PackageFileKind::File => 0o644,
    }
}

fn open_regular_source(path: &Path, display_path: &str) -> Result<File, BuilderError> {
    let file = open_source_no_follow(path).map_err(|error| BuilderError::Io {
        operation: "open package source file",
        path: display_path.to_string(),
        message: error.to_string(),
    })?;
    let metadata = file.metadata().map_err(|error| BuilderError::Io {
        operation: "inspect opened package source file",
        path: display_path.to_string(),
        message: error.to_string(),
    })?;
    if !metadata.is_file() {
        return Err(BuilderError::UnsafeSource(display_path.to_string()));
    }
    Ok(file)
}

#[cfg(unix)]
fn open_source_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

#[cfg(not(unix))]
fn open_source_no_follow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

fn hash_source_file(
    path: &Path,
    expected_size: u64,
    display_path: &str,
) -> Result<String, BuilderError> {
    let mut file = open_regular_source(path, display_path)?;
    let metadata = file.metadata().map_err(|error| BuilderError::Io {
        operation: "inspect package source size",
        path: display_path.to_string(),
        message: error.to_string(),
    })?;
    if metadata.len() != expected_size {
        return Err(BuilderError::SourceChanged(display_path.to_string()));
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let remaining = expected_size.saturating_sub(total);
        let read_limit = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
        let read = file
            .read(&mut buffer[..read_limit])
            .map_err(|error| BuilderError::Io {
                operation: "hash package source file",
                path: display_path.to_string(),
                message: error.to_string(),
            })?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(BuilderError::Archive(ArchiveError::LengthOverflow))?;
        if total > expected_size {
            return Err(BuilderError::SourceChanged(display_path.to_string()));
        }
        hasher.update(&buffer[..read]);
    }
    if total != expected_size {
        return Err(BuilderError::SourceChanged(display_path.to_string()));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn copy_verified_payload<W: Write>(
    entry: &SourceEntry,
    writer: &mut W,
) -> Result<(), BuilderError> {
    let display_path = &entry.metadata.path;
    let expected_size = entry.metadata.size;
    let expected_digest =
        entry.metadata.sha256.as_deref().ok_or_else(|| {
            BuilderError::Archive(ArchiveError::InvalidDigest(display_path.clone()))
        })?;
    let mut file = open_regular_source(&entry.physical_path, display_path)?;
    let metadata = file.metadata().map_err(|error| BuilderError::Io {
        operation: "inspect package source before archive write",
        path: display_path.clone(),
        message: error.to_string(),
    })?;
    if metadata.len() != expected_size
        || source_mode(&metadata, PackageFileKind::File) != entry.metadata.mode
    {
        return Err(BuilderError::SourceChanged(display_path.clone()));
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let remaining = expected_size.saturating_sub(total);
        let read_limit = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
        let read = file
            .read(&mut buffer[..read_limit])
            .map_err(|error| BuilderError::Io {
                operation: "stream package source payload",
                path: display_path.clone(),
                message: error.to_string(),
            })?;
        if read == 0 {
            break;
        }
        let new_total = total
            .checked_add(read as u64)
            .ok_or(BuilderError::Archive(ArchiveError::LengthOverflow))?;
        if new_total > expected_size {
            return Err(BuilderError::SourceChanged(display_path.clone()));
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|error| BuilderError::Write(error.to_string()))?;
        hasher.update(&buffer[..read]);
        total = new_total;
    }
    if total != expected_size {
        return Err(BuilderError::SourceChanged(display_path.clone()));
    }
    let actual_digest = format!("{:x}", hasher.finalize());
    if actual_digest != expected_digest {
        return Err(BuilderError::Archive(ArchiveError::DigestMismatch {
            path: display_path.clone(),
            expected: expected_digest.to_string(),
            actual: actual_digest,
        }));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_archive::inspect_archive;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let count = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "deku-package-builder-{}-{count}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test root");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn package() -> PackageInfo {
        PackageInfo {
            name: "sample".to_string(),
            version: "1.02".to_string(),
            architecture: "x86_64".to_string(),
            abi: "deku1-linux-gnu".to_string(),
            license: "MIT".to_string(),
            dependencies: vec!["zlib".to_string(), "libc".to_string()],
        }
    }

    #[test]
    fn builds_a_deterministic_archive_from_a_source_directory() {
        let root = TestDirectory::new();
        let bin = root.0.join("usr").join("bin");
        let empty = root.0.join("usr").join("share").join("empty");
        fs::create_dir_all(&bin).expect("create bin");
        fs::create_dir_all(&empty).expect("create empty directory");
        fs::write(bin.join("sample"), b"sample executable bytes").expect("write fixture");
        fs::write(root.0.join("README"), b"sample package").expect("write README");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(bin.join("sample"), fs::Permissions::from_mode(0o755))
                .expect("set executable mode");
            fs::set_permissions(root.0.join("README"), fs::Permissions::from_mode(0o644))
                .expect("set README mode");
        }

        let mut first = Vec::new();
        let mut second = Vec::new();
        let first_size =
            write_archive_from_directory(&root.0, package(), &mut first).expect("build archive");
        let second_size =
            write_archive_from_directory(&root.0, package(), &mut second).expect("build archive");
        assert_eq!(first, second);
        assert_eq!(first_size as usize, first.len());
        assert_eq!(second_size as usize, second.len());

        let verified = inspect_archive(&mut Cursor::new(first)).expect("verify built archive");
        assert_eq!(verified.manifest.package.version, "1.2-0");
        assert_eq!(
            verified.manifest.package.dependencies,
            vec!["libc".to_string(), "zlib".to_string()]
        );
        assert!(
            verified
                .manifest
                .files
                .iter()
                .any(|entry| entry.path == "usr/share/empty")
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_world_writable_source_directories() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestDirectory::new();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777))
            .expect("make source directory unsafe");
        let mut output = Vec::new();
        assert!(matches!(
            write_archive_from_directory(&root.0, package(), &mut output),
            Err(BuilderError::UnsafeSource(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_world_writable_source_file_modes() {
        use std::os::unix::fs::PermissionsExt;

        let root = TestDirectory::new();
        let source = root.0.join("writable.txt");
        fs::write(&source, b"must not become a package file").expect("write fixture");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o666))
            .expect("set group/world writable file mode");
        let mut output = Vec::new();
        assert!(matches!(
            write_archive_from_directory(&root.0, package(), &mut output),
            Err(BuilderError::Archive(ArchiveError::InvalidMode { .. }))
        ));
        assert!(output.is_empty());
    }

    struct MutatingWriter {
        bytes: Vec<u8>,
        path: PathBuf,
        changed: bool,
        mutate_permissions: bool,
    }

    impl Write for MutatingWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if !self.changed {
                if self.mutate_permissions {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
                            .expect("change source permissions");
                    }
                    #[cfg(not(unix))]
                    fs::write(&self.path, b"modified source bytes").expect("mutate source file");
                } else {
                    fs::write(&self.path, b"modified source bytes").expect("mutate source file");
                }
                self.changed = true;
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn detects_source_mutation_between_hashing_and_payload_streaming() {
        let root = TestDirectory::new();
        let source = root.0.join("sample.txt");
        fs::write(&source, b"original source bytes").expect("write source fixture");
        let mut output = MutatingWriter {
            bytes: Vec::new(),
            path: source,
            changed: false,
            mutate_permissions: false,
        };

        assert!(matches!(
            write_archive_from_directory(&root.0, package(), &mut output),
            Err(BuilderError::Archive(ArchiveError::DigestMismatch { .. }))
        ));
        assert!(output.changed);
        assert!(!output.bytes.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn detects_permission_changes_between_package_scan_and_payload_write() {
        let root = TestDirectory::new();
        let source = root.0.join("sample.txt");
        fs::write(&source, b"stable source bytes").expect("write source fixture");
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&source, fs::Permissions::from_mode(0o644))
                .expect("set initial mode");
        }
        let mut output = MutatingWriter {
            bytes: Vec::new(),
            path: source,
            changed: false,
            mutate_permissions: true,
        };

        assert!(matches!(
            write_archive_from_directory(&root.0, package(), &mut output),
            Err(BuilderError::SourceChanged(_))
        ));
        assert!(output.changed);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks_inside_the_source_tree() {
        use std::os::unix::fs::symlink;

        let root = TestDirectory::new();
        fs::write(root.0.join("good"), b"good").expect("write fixture");
        symlink(root.0.join("good"), root.0.join("linked")).expect("create symlink");
        let mut output = Vec::new();
        assert!(matches!(
            write_archive_from_directory(&root.0, package(), &mut output),
            Err(BuilderError::UnsafeSource(_))
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn rejects_a_symlink_as_the_source_root() {
        let root = TestDirectory::new();
        let target = root.0.join("real");
        fs::create_dir(&target).expect("create target directory");
        let link = root.0.join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        #[cfg(not(unix))]
        {
            let _ = &link;
            return;
        }

        let mut output = Vec::new();
        assert!(matches!(
            write_archive_from_directory(&link, package(), &mut output),
            Err(BuilderError::UnsafeSource(_))
        ));
    }
}
