//! Durable, monotonic storage for the installed-package database.
//!
//! Saves are serialized across processes, validated before publication, written
//! to a private temporary file, synced, and atomically renamed. This stores the
//! database only; it does not prove the actual filesystem matches the database
//! and does not execute installation or removal operations.

use crate::ownership::{InstalledDatabase, OwnershipError};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const DATABASE_FILE_NAME: &str = "installed.json";
const LOCK_FILE_NAME: &str = ".installed-db.lock";
const MAX_DATABASE_BYTES: usize = 64 * 1024 * 1024;
const MAX_TEMP_ATTEMPTS: u32 = 32;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseStoreError {
    UnsafeDirectory,
    UnsafeDatabaseFile,
    UnsafeLockFile,
    DatabaseTooLarge { size: usize, limit: usize },
    InvalidDatabase(String),
    StaleGeneration {
        existing_generation: u64,
        proposed_generation: u64,
    },
    UnsupportedPlatform,
    Io {
        operation: &'static str,
        message: String,
    },
}

impl std::fmt::Display for DatabaseStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeDirectory => write!(
                f,
                "installed database directory must be owned by the effective user and not writable by group or others"
            ),
            Self::UnsafeDatabaseFile => write!(
                f,
                "installed database path must be a regular, owned, non-symlink file"
            ),
            Self::UnsafeLockFile => write!(
                f,
                "installed database lock must be a regular, owned, protected file"
            ),
            Self::DatabaseTooLarge { size, limit } => {
                write!(f, "installed database is {size} bytes; maximum is {limit}")
            }
            Self::InvalidDatabase(message) => {
                write!(f, "installed database is invalid: {message}")
            }
            Self::StaleGeneration {
                existing_generation,
                proposed_generation,
            } => write!(
                f,
                "refusing installed database generation {proposed_generation}; current generation is {existing_generation}"
            ),
            Self::UnsupportedPlatform => {
                write!(f, "durable installed database locking is supported on Unix platforms only")
            }
            Self::Io { operation, message } => write!(f, "{operation} failed: {message}"),
        }
    }
}

impl std::error::Error for DatabaseStoreError {}

impl From<OwnershipError> for DatabaseStoreError {
    fn from(value: OwnershipError) -> Self {
        Self::InvalidDatabase(value.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct InstalledDatabaseStore {
    directory: PathBuf,
}

impl InstalledDatabaseStore {
    /// Open an existing, pre-provisioned protected directory. This does not
    /// create directories or silently change their permissions.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, DatabaseStoreError> {
        let path = directory.as_ref();
        let metadata = fs::symlink_metadata(path).map_err(|error| DatabaseStoreError::Io {
            operation: "inspect installed database directory",
            message: error.to_string(),
        })?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(DatabaseStoreError::UnsafeDirectory);
        }
        ensure_private_directory(&metadata)?;
        let canonical = fs::canonicalize(path).map_err(|error| DatabaseStoreError::Io {
            operation: "canonicalize installed database directory",
            message: error.to_string(),
        })?;
        Ok(Self {
            directory: canonical,
        })
    }

    pub fn path(&self) -> PathBuf {
        self.directory.join(DATABASE_FILE_NAME)
    }

    pub fn load(&self) -> Result<InstalledDatabase, DatabaseStoreError> {
        self.read_database_file()
    }

    /// Persist a validated database if its generation is newer than the current
    /// one. Re-saving an identical generation is idempotent; a divergent state
    /// at the same generation is rejected.
    pub fn save(&self, database: &InstalledDatabase) -> Result<PathBuf, DatabaseStoreError> {
        database.validate()?;
        let bytes = database.to_json()?;
        if bytes.len() > MAX_DATABASE_BYTES {
            return Err(DatabaseStoreError::DatabaseTooLarge {
                size: bytes.len(),
                limit: MAX_DATABASE_BYTES,
            });
        }

        let _lock = acquire_database_lock(&self.directory)?;
        let destination = self.path();
        if let Some(existing) = self.read_existing_database()? {
            if existing == *database {
                return Ok(destination);
            }
            if database.generation <= existing.generation {
                return Err(DatabaseStoreError::StaleGeneration {
                    existing_generation: existing.generation,
                    proposed_generation: database.generation,
                });
            }
        }

        let temporary = self.write_temporary_database(&bytes)?;
        if let Err(error) = fs::rename(&temporary, &destination) {
            let _ = fs::remove_file(&temporary);
            return Err(DatabaseStoreError::Io {
                operation: "atomically replace installed database",
                message: error.to_string(),
            });
        }
        File::open(&self.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| DatabaseStoreError::Io {
                operation: "sync installed database directory",
                message: error.to_string(),
            })?;
        Ok(destination)
    }

    fn read_existing_database(&self) -> Result<Option<InstalledDatabase>, DatabaseStoreError> {
        let path = self.path();
        match fs::symlink_metadata(&path) {
            Ok(_) => self.read_database_file().map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(DatabaseStoreError::Io {
                operation: "inspect current installed database",
                message: error.to_string(),
            }),
        }
    }

    fn read_database_file(&self) -> Result<InstalledDatabase, DatabaseStoreError> {
        let path = self.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| DatabaseStoreError::Io {
            operation: "inspect installed database file",
            message: error.to_string(),
        })?;
        ensure_private_database_file(&metadata)?;
        if metadata.len() > MAX_DATABASE_BYTES as u64 {
            return Err(DatabaseStoreError::DatabaseTooLarge {
                size: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
                limit: MAX_DATABASE_BYTES,
            });
        }

        let file = open_database_file(&path).map_err(|error| {
            if is_symlink_open_error(&error) {
                DatabaseStoreError::UnsafeDatabaseFile
            } else {
                DatabaseStoreError::Io {
                    operation: "open installed database without following symlinks",
                    message: error.to_string(),
                }
            }
        })?;
        let opened_metadata = file.metadata().map_err(|error| DatabaseStoreError::Io {
            operation: "inspect opened installed database",
            message: error.to_string(),
        })?;
        ensure_private_database_file(&opened_metadata)?;
        if opened_metadata.len() > MAX_DATABASE_BYTES as u64 {
            return Err(DatabaseStoreError::DatabaseTooLarge {
                size: usize::try_from(opened_metadata.len()).unwrap_or(usize::MAX),
                limit: MAX_DATABASE_BYTES,
            });
        }

        let mut bytes = Vec::new();
        file.take((MAX_DATABASE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| DatabaseStoreError::Io {
                operation: "read installed database",
                message: error.to_string(),
            })?;
        if bytes.len() > MAX_DATABASE_BYTES {
            return Err(DatabaseStoreError::DatabaseTooLarge {
                size: bytes.len(),
                limit: MAX_DATABASE_BYTES,
            });
        }
        InstalledDatabase::from_json(&bytes)
            .map_err(|error| DatabaseStoreError::InvalidDatabase(error.to_string()))
    }

    fn write_temporary_database(&self, bytes: &[u8]) -> Result<PathBuf, DatabaseStoreError> {
        for _ in 0..MAX_TEMP_ATTEMPTS {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let name = format!(
                ".installed-db.tmp-{}-{timestamp}-{counter}",
                std::process::id()
            );
            let path = self.directory.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            }
            let mut file = match options.open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(DatabaseStoreError::Io {
                        operation: "create temporary installed database",
                        message: error.to_string(),
                    });
                }
            };
            let result = file
                .write_all(bytes)
                .and_then(|()| file.sync_all())
                .map_err(|error| DatabaseStoreError::Io {
                    operation: "write temporary installed database",
                    message: error.to_string(),
                });
            if let Err(error) = result {
                drop(file);
                let _ = fs::remove_file(&path);
                return Err(error);
            }
            return Ok(path);
        }
        Err(DatabaseStoreError::Io {
            operation: "create temporary installed database",
            message: "temporary-name attempt limit exceeded".to_string(),
        })
    }
}

#[cfg(unix)]
struct DatabaseLock(File);

#[cfg(unix)]
impl Drop for DatabaseLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: the lock file is owned by this guard and still has a live descriptor.
        unsafe {
            let _ = libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(unix)]
fn acquire_database_lock(directory: &Path) -> Result<DatabaseLock, DatabaseStoreError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    let path = directory.join(LOCK_FILE_NAME);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(&path).map_err(|error| {
        if is_symlink_open_error(&error) {
            DatabaseStoreError::UnsafeLockFile
        } else {
            DatabaseStoreError::Io {
                operation: "open installed database lock",
                message: error.to_string(),
            }
        }
    })?;
    let metadata = file.metadata().map_err(|error| DatabaseStoreError::Io {
        operation: "inspect installed database lock",
        message: error.to_string(),
    })?;
    ensure_private_lock_file(&metadata)?;

    loop {
        // SAFETY: flock operates on the valid descriptor owned by file.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if result == 0 {
            return Ok(DatabaseLock(file));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(DatabaseStoreError::Io {
                operation: "lock installed database",
                message: error.to_string(),
            });
        }
    }
}

#[cfg(not(unix))]
struct DatabaseLock;

#[cfg(not(unix))]
fn acquire_database_lock(_directory: &Path) -> Result<DatabaseLock, DatabaseStoreError> {
    Err(DatabaseStoreError::UnsupportedPlatform)
}

#[cfg(unix)]
fn ensure_private_directory(metadata: &fs::Metadata) -> Result<(), DatabaseStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // SAFETY: geteuid has no pointer arguments or preconditions.
    let effective_uid = unsafe { libc::geteuid() as u32 };
    if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o022 != 0 {
        return Err(DatabaseStoreError::UnsafeDirectory);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_directory(_metadata: &fs::Metadata) -> Result<(), DatabaseStoreError> {
    Err(DatabaseStoreError::UnsupportedPlatform)
}

#[cfg(unix)]
fn ensure_private_database_file(metadata: &fs::Metadata) -> Result<(), DatabaseStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // SAFETY: geteuid has no pointer arguments or preconditions.
    let effective_uid = unsafe { libc::geteuid() as u32 };
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(DatabaseStoreError::UnsafeDatabaseFile);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_database_file(metadata: &fs::Metadata) -> Result<(), DatabaseStoreError> {
    if !metadata.is_file() {
        return Err(DatabaseStoreError::UnsafeDatabaseFile);
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_lock_file(metadata: &fs::Metadata) -> Result<(), DatabaseStoreError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // SAFETY: geteuid has no pointer arguments or preconditions.
    let effective_uid = unsafe { libc::geteuid() as u32 };
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(DatabaseStoreError::UnsafeLockFile);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_lock_file(_metadata: &fs::Metadata) -> Result<(), DatabaseStoreError> {
    Err(DatabaseStoreError::UnsupportedPlatform)
}

#[cfg(unix)]
fn open_database_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

#[cfg(not(unix))]
fn open_database_file(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(unix)]
fn is_symlink_open_error(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(unix))]
fn is_symlink_open_error(_error: &std::io::Error) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ownership::{InstalledDatabase, InstalledPackageRecord};
    use crate::package_archive::{
        PackageFileKind, PackageInfo, PackageInputEntry, encode_archive, inspect_archive,
    };
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let number = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "deku-installed-db-store-{}-{number}",
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
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn package_manifest(name: &str, content: &[u8]) -> crate::package_archive::PackageArchiveManifest {
        let package = PackageInfo {
            name: name.to_string(),
            version: "1.0-1".to_string(),
            architecture: "x86_64".to_string(),
            abi: "deku1-linux-gnu".to_string(),
            license: "MIT".to_string(),
            dependencies: Vec::new(),
        };
        let archive = encode_archive(
            package,
            vec![PackageInputEntry {
                path: format!("usr/bin/{name}"),
                kind: PackageFileKind::File,
                mode: 0o644,
                content: content.to_vec(),
            }],
        )
        .expect("encode fixture archive");
        inspect_archive(&mut Cursor::new(archive))
            .expect("inspect fixture archive")
            .manifest
    }

    fn database(generation: u64, name: &str, content: &[u8]) -> InstalledDatabase {
        InstalledDatabase::from_manifests(generation, [package_manifest(name, content)])
            .expect("create installed database")
    }

    #[test]
    fn saves_and_loads_database_with_idempotent_repeat() {
        let temp = TestDirectory::new();
        let store = InstalledDatabaseStore::open(&temp.0).expect("open database store");
        let proposed = database(1, "app", b"one");
        let path = store.save(&proposed).expect("save database");
        assert_eq!(path, store.path());
        assert_eq!(store.load().expect("load database"), proposed);
        assert_eq!(store.save(&proposed).expect("idempotent save"), path);
    }

    #[test]
    fn rejects_stale_and_divergent_database_generations() {
        let temp = TestDirectory::new();
        let store = InstalledDatabaseStore::open(&temp.0).expect("open database store");
        store.save(&database(2, "app", b"new")).expect("save newer DB");
        assert!(matches!(
            store.save(&database(1, "app", b"old")),
            Err(DatabaseStoreError::StaleGeneration {
                existing_generation: 2,
                proposed_generation: 1
            })
        ));
        assert!(matches!(
            store.save(&database(2, "other", b"different")),
            Err(DatabaseStoreError::StaleGeneration {
                existing_generation: 2,
                proposed_generation: 2
            })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_and_group_world_writable_database_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TestDirectory::new();
        let store = InstalledDatabaseStore::open(&temp.0).expect("open database store");
        store.save(&database(1, "app", b"good")).expect("save database");
        let path = store.path();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
            .expect("make database insecure");
        assert!(matches!(
            store.load(),
            Err(DatabaseStoreError::UnsafeDatabaseFile)
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restore private permissions");
        let external = temp.0.join("external.json");
        fs::write(&external, InstalledDatabase::empty().to_json().unwrap())
            .expect("write external JSON");
        fs::remove_file(&path).expect("remove database");
        symlink(&external, &path).expect("replace database with symlink");
        assert!(matches!(
            store.load(),
            Err(DatabaseStoreError::UnsafeDatabaseFile)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn serializes_competing_generations_and_rejects_one_stale_writer() {
        let temp = TestDirectory::new();
        let store = InstalledDatabaseStore::open(&temp.0).expect("open database store");
        store.save(&InstalledDatabase::empty()).expect("save initial database");
        let left_db = database(1, "left-app", b"left");
        let right_db = database(1, "right-app", b"right");

        let barrier = Arc::new(Barrier::new(3));
        let left_store = store.clone();
        let left_barrier = barrier.clone();
        let left = thread::spawn(move || {
            left_barrier.wait();
            left_store.save(&left_db)
        });
        let right_store = store.clone();
        let right_barrier = barrier.clone();
        let right = thread::spawn(move || {
            right_barrier.wait();
            right_store.save(&right_db)
        });
        barrier.wait();

        let results = [left.join().unwrap(), right.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(DatabaseStoreError::StaleGeneration { .. })))
                .count(),
            1
        );
        assert_eq!(store.load().unwrap().generation, 1);
    }
}
