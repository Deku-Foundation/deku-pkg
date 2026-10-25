//! Safe extraction of verified Deku package archive v1 into an empty staging root.
//!
//! This module is a staging primitive only. It never writes to a live system
//! root, executes package code, or decides package ownership/conflict policy.
//! Archive v1 has no symlinks or special files, which keeps extraction policy
//! explicit while the transaction executor is still under development.

use crate::package_archive::{
    ArchiveError, PackageArchiveManifest, PackageFileKind, PackageInfo, VerifiedArchive,
    inspect_archive,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

const HEADER_LEN: usize = 20;
const HASH_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractionError {
    Archive(ArchiveError),
    UnsafeDestination,
    DestinationNotEmpty,
    SourceChanged(String),
    Io {
        operation: &'static str,
        path: String,
        message: String,
    },
}

impl std::fmt::Display for ExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ExtractionError {}

impl From<ArchiveError> for ExtractionError {
    fn from(value: ArchiveError) -> Self {
        Self::Archive(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractionReport {
    pub package: PackageInfo,
    pub archive_bytes: u64,
    pub payload_bytes: u64,
    pub files_written: usize,
    pub directories_created: usize,
}

/// Verify and extract an archive to an existing, empty, protected directory.
///
/// The archive is verified once before destination mutation, then its manifest
/// and each payload digest are checked again while writing. If extraction fails,
/// this function best-effort removes only paths it created and leaves the
/// destination root itself in place.
pub fn extract_archive_to_empty_directory<R: Read + Seek>(
    reader: &mut R,
    destination: impl AsRef<Path>,
) -> Result<ExtractionReport, ExtractionError> {
    let verified = inspect_archive(reader)?;
    let root = validate_empty_destination(destination.as_ref())?;

    let mut created_files = Vec::<PathBuf>::new();
    let mut created_directories = Vec::<PathBuf>::new();
    let mut created_directory_names = BTreeSet::<String>::new();

    let result = extract_verified(
        reader,
        &root,
        &verified,
        &mut created_files,
        &mut created_directories,
        &mut created_directory_names,
    );

    match result {
        Ok(report) => Ok(report),
        Err(error) => {
            cleanup_staging(&created_files, &created_directories);
            Err(error)
        }
    }
}

fn validate_empty_destination(path: &Path) -> Result<PathBuf, ExtractionError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| ExtractionError::Io {
        operation: "inspect extraction destination",
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ExtractionError::UnsafeDestination);
    }
    ensure_private_destination(&metadata)?;
    let canonical = fs::canonicalize(path).map_err(|error| ExtractionError::Io {
        operation: "canonicalize extraction destination",
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    let mut entries = fs::read_dir(&canonical).map_err(|error| ExtractionError::Io {
        operation: "inspect extraction destination contents",
        path: canonical.display().to_string(),
        message: error.to_string(),
    })?;
    if entries
        .next()
        .transpose()
        .map_err(|error| ExtractionError::Io {
            operation: "read extraction destination contents",
            path: canonical.display().to_string(),
            message: error.to_string(),
        })?
        .is_some()
    {
        return Err(ExtractionError::DestinationNotEmpty);
    }
    Ok(canonical)
}

#[cfg(unix)]
fn ensure_private_destination(metadata: &fs::Metadata) -> Result<(), ExtractionError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // The staging directory must be controlled by the current package-manager
    // process, not merely happen to have non-public permission bits.
    // SAFETY: geteuid has no pointer arguments or preconditions.
    let effective_uid = unsafe { libc::geteuid() as u32 };
    if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o022 != 0 {
        return Err(ExtractionError::UnsafeDestination);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_destination(_metadata: &fs::Metadata) -> Result<(), ExtractionError> {
    // This prototype targets Linux; secure ownership checks must be specified
    // separately before enabling extraction on other platforms.
    Err(ExtractionError::UnsafeDestination)
}

fn extract_verified<R: Read + Seek>(
    reader: &mut R,
    root: &Path,
    verified: &VerifiedArchive,
    created_files: &mut Vec<PathBuf>,
    created_directories: &mut Vec<PathBuf>,
    created_directory_names: &mut BTreeSet<String>,
) -> Result<ExtractionReport, ExtractionError> {
    let manifest = read_and_compare_manifest(reader, verified)?;
    let mut directory_modes = BTreeMap::<String, u32>::new();

    // Build directories before payload files. The archive manifest is sorted,
    // but parents may be implicit, so create each path component explicitly.
    for entry in &manifest.files {
        let relative = safe_relative_path(&entry.path)?;
        ensure_parent_directories(
            root,
            &relative,
            created_directories,
            created_directory_names,
        )?;

        if entry.kind == PackageFileKind::Directory {
            let full_path = root.join(&relative);
            let relative_name = entry.path.clone();
            if created_directory_names.contains(&relative_name) {
                let metadata = fs::symlink_metadata(&full_path)
                    .map_err(|error| io_error("inspect staged directory", &full_path, error))?;
                if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                    return Err(ExtractionError::UnsafeDestination);
                }
            } else {
                fs::create_dir(&full_path)
                    .map_err(|error| io_error("create staged directory", &full_path, error))?;
                set_mode(&full_path, 0o700)
                    .map_err(|error| io_error("protect staged directory", &full_path, error))?;
                created_directories.push(full_path);
                created_directory_names.insert(relative_name.clone());
            }
            directory_modes.insert(relative_name, entry.mode);
        }
    }

    let mut payload_total = 0_u64;
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    for entry in &manifest.files {
        if entry.kind != PackageFileKind::File {
            continue;
        }

        let relative = safe_relative_path(&entry.path)?;
        let output_path = root.join(&relative);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(&output_path)
            .map_err(|error| io_error("create staged package file", &output_path, error))?;
        created_files.push(output_path.clone());

        let expected_digest = entry
            .sha256
            .as_deref()
            .ok_or_else(|| ExtractionError::SourceChanged(entry.path.clone()))?;
        let mut hasher = Sha256::new();
        let mut remaining = entry.size;
        while remaining > 0 {
            let chunk_len = remaining.min(buffer.len() as u64) as usize;
            reader
                .read_exact(&mut buffer[..chunk_len])
                .map_err(|error| ExtractionError::Io {
                    operation: "read package payload during extraction",
                    path: entry.path.clone(),
                    message: error.to_string(),
                })?;
            output
                .write_all(&buffer[..chunk_len])
                .map_err(|error| io_error("write staged package file", &output_path, error))?;
            hasher.update(&buffer[..chunk_len]);
            remaining -= chunk_len as u64;
            payload_total = payload_total
                .checked_add(chunk_len as u64)
                .ok_or_else(|| ExtractionError::SourceChanged(entry.path.clone()))?;
        }
        let actual_digest = format!("{:x}", hasher.finalize());
        if actual_digest != expected_digest {
            return Err(ExtractionError::SourceChanged(format!(
                "payload digest changed for {}",
                entry.path
            )));
        }
        output
            .sync_all()
            .map_err(|error| io_error("sync staged package file", &output_path, error))?;
        set_file_mode(&output, entry.mode)
            .map_err(|error| io_error("apply staged file permissions", &output_path, error))?;
        output
            .sync_all()
            .map_err(|error| io_error("sync staged file permissions", &output_path, error))?;
        drop(output);
    }

    if payload_total != verified.payload_size {
        return Err(ExtractionError::SourceChanged(
            "payload length changed after archive verification".to_string(),
        ));
    }

    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|error| ExtractionError::Io {
            operation: "check archive end during extraction",
            path: "<archive>".to_string(),
            message: error.to_string(),
        })?
        != 0
    {
        return Err(ExtractionError::SourceChanged(
            "archive has trailing data after verification".to_string(),
        ));
    }
    let final_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| ExtractionError::Io {
            operation: "recheck archive size after extraction",
            path: "<archive>".to_string(),
            message: error.to_string(),
        })?;
    if final_size != verified.archive_size {
        return Err(ExtractionError::SourceChanged(
            "archive size changed during extraction".to_string(),
        ));
    }

    // Deepest-first keeps parents searchable until all child permissions have
    // been applied. Implicit directories receive the default 0755 mode.
    created_directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in created_directories.iter() {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ExtractionError::UnsafeDestination)?;
        let key = relative
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        let mode = directory_modes.get(&key).copied().unwrap_or(0o755);
        set_mode(path, mode)
            .map_err(|error| io_error("apply staged directory permissions", path, error))?;
    }
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error("sync extraction root", root, error))?;

    let files_written = manifest
        .files
        .iter()
        .filter(|entry| entry.kind == PackageFileKind::File)
        .count();
    Ok(ExtractionReport {
        package: manifest.package,
        archive_bytes: verified.archive_size,
        payload_bytes: payload_total,
        files_written,
        directories_created: created_directories.len(),
    })
}

fn read_and_compare_manifest<R: Read + Seek>(
    reader: &mut R,
    verified: &VerifiedArchive,
) -> Result<PackageArchiveManifest, ExtractionError> {
    let size = reader
        .seek(SeekFrom::End(0))
        .map_err(|error| ExtractionError::Io {
            operation: "recheck archive before extraction",
            path: "<archive>".to_string(),
            message: error.to_string(),
        })?;
    if size != verified.archive_size {
        return Err(ExtractionError::SourceChanged(
            "archive size changed after verification".to_string(),
        ));
    }
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| ExtractionError::Io {
            operation: "rewind archive before extraction",
            path: "<archive>".to_string(),
            message: error.to_string(),
        })?;
    let mut header = [0_u8; HEADER_LEN];
    reader
        .read_exact(&mut header)
        .map_err(|error| ExtractionError::Io {
            operation: "read archive header before extraction",
            path: "<archive>".to_string(),
            message: error.to_string(),
        })?;
    if &header[..8] != b"DEKUPK01" {
        return Err(ExtractionError::SourceChanged(
            "archive magic changed after verification".to_string(),
        ));
    }
    let manifest_len = u32::from_be_bytes(header[8..12].try_into().map_err(|_| {
        ExtractionError::SourceChanged("archive manifest length changed".to_string())
    })?) as usize;
    let payload_len = u64::from_be_bytes(header[12..20].try_into().map_err(|_| {
        ExtractionError::SourceChanged("archive payload length changed".to_string())
    })?);
    if payload_len != verified.payload_size
        || HEADER_LEN as u64 + manifest_len as u64 + payload_len != verified.archive_size
    {
        return Err(ExtractionError::SourceChanged(
            "archive framing changed after verification".to_string(),
        ));
    }

    let mut manifest_bytes = vec![0_u8; manifest_len];
    reader
        .read_exact(&mut manifest_bytes)
        .map_err(|error| ExtractionError::Io {
            operation: "read archive manifest before extraction",
            path: "<archive>".to_string(),
            message: error.to_string(),
        })?;
    let manifest: PackageArchiveManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| ExtractionError::Archive(ArchiveError::InvalidJson(error.to_string())))?;
    if manifest != verified.manifest {
        return Err(ExtractionError::SourceChanged(
            "archive manifest changed after verification".to_string(),
        ));
    }
    Ok(manifest)
}

fn safe_relative_path(value: &str) -> Result<PathBuf, ExtractionError> {
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ExtractionError::Archive(ArchiveError::InvalidPath(
            value.to_string(),
        )));
    }
    Ok(path.to_path_buf())
}

fn ensure_parent_directories(
    root: &Path,
    relative: &Path,
    created_directories: &mut Vec<PathBuf>,
    created_directory_names: &mut BTreeSet<String>,
) -> Result<(), ExtractionError> {
    let Some(parent) = relative.parent() else {
        return Err(ExtractionError::UnsafeDestination);
    };
    let mut current = root.to_path_buf();
    let mut relative_name = String::new();
    for component in parent.components() {
        let Component::Normal(name) = component else {
            return Err(ExtractionError::UnsafeDestination);
        };
        if !relative_name.is_empty() {
            relative_name.push('/');
        }
        relative_name.push_str(name.to_str().ok_or(ExtractionError::UnsafeDestination)?);
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir()
                    || metadata.file_type().is_symlink()
                    || !created_directory_names.contains(&relative_name)
                {
                    return Err(ExtractionError::UnsafeDestination);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    io_error("create implicit package directory", &current, error)
                })?;
                set_mode(&current, 0o700).map_err(|error| {
                    io_error("protect implicit package directory", &current, error)
                })?;
                created_directories.push(current.clone());
                created_directory_names.insert(relative_name.clone());
            }
            Err(error) => {
                return Err(io_error(
                    "inspect package parent directory",
                    &current,
                    error,
                ));
            }
        }
    }
    Ok(())
}

fn cleanup_staging(files: &[PathBuf], directories: &[PathBuf]) {
    let mut directories = directories.to_vec();
    directories.sort_by_key(|path| path.components().count());
    for directory in &directories {
        let _ = set_mode(directory, 0o700);
    }
    for file in files.iter().rev() {
        let _ = fs::remove_file(file);
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in &directories {
        let _ = fs::remove_dir(directory);
    }
}

fn io_error(operation: &'static str, path: &Path, error: std::io::Error) -> ExtractionError {
    ExtractionError::Io {
        operation,
        path: path.display().to_string(),
        message: error.to_string(),
    }
}

#[cfg(unix)]
fn set_file_mode(file: &File, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_file_mode(file: &File, mode: u32) -> std::io::Result<()> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    file.set_permissions(permissions)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(mode & 0o222 == 0);
    fs::set_permissions(path, permissions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_archive::{PackageInputEntry, encode_archive};
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let number = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "deku-package-extract-{}-{number}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("protect test directory");
            }
            Self(path)
        }

        fn child(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir(&path).expect("create test child directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("protect test child");
            }
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_archive() -> Vec<u8> {
        let package = PackageInfo {
            name: "extract-fixture".to_string(),
            version: "1.0-1".to_string(),
            architecture: "x86_64".to_string(),
            abi: "deku1-linux-gnu".to_string(),
            license: "MIT".to_string(),
            dependencies: vec![],
        };
        encode_archive(
            package,
            vec![
                PackageInputEntry {
                    path: "usr".to_string(),
                    kind: PackageFileKind::Directory,
                    mode: 0o755,
                    content: vec![],
                },
                PackageInputEntry {
                    path: "usr/bin".to_string(),
                    kind: PackageFileKind::Directory,
                    mode: 0o755,
                    content: vec![],
                },
                PackageInputEntry {
                    path: "usr/bin/tool".to_string(),
                    kind: PackageFileKind::File,
                    mode: 0o755,
                    content: b"native tool bytes".to_vec(),
                },
                PackageInputEntry {
                    path: "var/empty".to_string(),
                    kind: PackageFileKind::Directory,
                    mode: 0o750,
                    content: vec![],
                },
            ],
        )
        .expect("encode fixture archive")
    }

    #[test]
    fn extracts_verified_files_and_directory_modes_to_empty_staging_root() {
        let temp = TestDirectory::new();
        let destination = temp.child("stage");
        let archive = fixture_archive();
        let report = extract_archive_to_empty_directory(&mut Cursor::new(&archive), &destination)
            .expect("extract fixture archive");
        assert_eq!(report.package.name, "extract-fixture");
        assert_eq!(report.files_written, 1);
        assert_eq!(report.directories_created, 4);
        assert_eq!(report.payload_bytes, b"native tool bytes".len() as u64);
        assert_eq!(
            fs::read(destination.join("usr/bin/tool")).expect("read extracted file"),
            b"native tool bytes"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(destination.join("usr/bin/tool"))
                    .expect("stat extracted file")
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
            assert_eq!(
                fs::metadata(destination.join("var/empty"))
                    .expect("stat extracted directory")
                    .permissions()
                    .mode()
                    & 0o777,
                0o750
            );
        }
    }

    #[test]
    fn rejects_nonempty_destination_without_changing_existing_contents() {
        let temp = TestDirectory::new();
        let destination = temp.child("stage");
        fs::write(destination.join("keep"), b"keep").expect("create sentinel");
        let error =
            extract_archive_to_empty_directory(&mut Cursor::new(fixture_archive()), &destination)
                .expect_err("non-empty destination must be rejected");
        assert_eq!(error, ExtractionError::DestinationNotEmpty);
        assert_eq!(
            fs::read(destination.join("keep")).expect("read sentinel"),
            b"keep"
        );
    }

    #[test]
    fn rejects_tampered_archive_before_creating_any_payload() {
        let temp = TestDirectory::new();
        let destination = temp.child("stage");
        let mut archive = fixture_archive();
        let payload_offset = archive.len() - b"native tool bytes".len();
        archive[payload_offset] ^= 0x01;
        assert!(matches!(
            extract_archive_to_empty_directory(&mut Cursor::new(archive), &destination),
            Err(ExtractionError::Archive(
                ArchiveError::DigestMismatch { .. }
            ))
        ));
        assert!(
            fs::read_dir(destination)
                .expect("list stage")
                .next()
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_destination() {
        use std::os::unix::fs::symlink;
        let temp = TestDirectory::new();
        let real = temp.child("real");
        let link = temp.0.join("link");
        symlink(&real, &link).expect("create destination symlink");
        assert!(matches!(
            extract_archive_to_empty_directory(&mut Cursor::new(fixture_archive()), &link),
            Err(ExtractionError::UnsafeDestination)
        ));
    }
}
