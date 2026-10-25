//! Content-addressed immutable object store for verified artifacts.
//!
//! Objects are named by their lowercase SHA-256 digest. Ingestion streams to a
//! private temporary file, enforces a caller-supplied byte limit, verifies the
//! digest, syncs the file, marks it read-only, and publishes it without
//! overwriting an existing object. This module does not extract packages,
//! install files, authenticate repository metadata, or mutate a system root.

use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HASH_BUFFER_BYTES: usize = 64 * 1024;
const MAX_TEMP_NAME_ATTEMPTS: u32 = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentStoreError {
    InvalidDigest,
    UnsafeDirectory,
    UnsafeObject,
    ObjectTooLarge { size: u64, limit: u64 },
    DigestMismatch { expected: String, actual: String },
    CorruptExistingObject,
    Io { operation: &'static str, message: String },
}

impl std::fmt::Display for ContentStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDigest => write!(f, "object identifier must be a lowercase SHA-256 digest"),
            Self::UnsafeDirectory => write!(
                f,
                "content store must be an existing non-symlink directory not writable by group or others"
            ),
            Self::UnsafeObject => write!(f, "object path is not a regular non-symlink file"),
            Self::ObjectTooLarge { size, limit } => {
                write!(f, "object is {size} bytes; maximum is {limit}")
            }
            Self::DigestMismatch { expected, actual } => {
                write!(f, "object digest mismatch: expected {expected}, got {actual}")
            }
            Self::CorruptExistingObject => {
                write!(f, "an existing object with this digest is corrupt")
            }
            Self::Io { operation, message } => write!(f, "{operation} failed: {message}"),
        }
    }
}

impl std::error::Error for ContentStoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredObject {
    pub sha256: String,
    pub size: u64,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ContentStore {
    directory: PathBuf,
}

impl ContentStore {
    /// Open an existing protected directory; never creates it or changes its
    /// permissions. Provisioning is an explicit installation/setup step.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, ContentStoreError> {
        let path = directory.as_ref();
        let metadata = fs::symlink_metadata(path).map_err(|error| ContentStoreError::Io {
            operation: "inspect content-store directory",
            message: error.to_string(),
        })?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(ContentStoreError::UnsafeDirectory);
        }
        ensure_private_directory(&metadata)?;

        let canonical = fs::canonicalize(path).map_err(|error| ContentStoreError::Io {
            operation: "canonicalize content-store directory",
            message: error.to_string(),
        })?;
        Ok(Self { directory: canonical })
    }

    /// Store a stream only when its complete SHA-256 matches expected_sha256.
    /// The stream is bounded even when the reader never reaches EOF.
    pub fn put_reader<R: Read>(
        &self,
        mut reader: R,
        expected_sha256: &str,
        max_bytes: u64,
    ) -> Result<StoredObject, ContentStoreError> {
        if !valid_digest(expected_sha256) {
            return Err(ContentStoreError::InvalidDigest);
        }

        let destination = self.path_for(expected_sha256)?;
        let (temporary, mut file) = self.create_temporary_file()?;
        let result = (|| {
            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; HASH_BUFFER_BYTES];
            let mut total = 0_u64;

            loop {
                let remaining = max_bytes.saturating_sub(total);
                let read_limit = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
                let read = loop {
                    match reader.read(&mut buffer[..read_limit]) {
                        Ok(read) => break read,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            return Err(ContentStoreError::Io {
                                operation: "read incoming object",
                                message: error.to_string(),
                            });
                        }
                    }
                };

                if read == 0 {
                    break;
                }
                total = total
                    .checked_add(read as u64)
                    .ok_or(ContentStoreError::ObjectTooLarge {
                        size: u64::MAX,
                        limit: max_bytes,
                    })?;
                if total > max_bytes {
                    return Err(ContentStoreError::ObjectTooLarge {
                        size: total,
                        limit: max_bytes,
                    });
                }

                hasher.update(&buffer[..read]);
                file.write_all(&buffer[..read])
                    .map_err(|error| ContentStoreError::Io {
                        operation: "write temporary object",
                        message: error.to_string(),
                    })?;
            }

            let actual_sha256 = format!("{:x}", hasher.finalize());
            if actual_sha256 != expected_sha256 {
                return Err(ContentStoreError::DigestMismatch {
                    expected: expected_sha256.to_string(),
                    actual: actual_sha256,
                });
            }

            file.sync_all().map_err(|error| ContentStoreError::Io {
                operation: "sync temporary object",
                message: error.to_string(),
            })?;
            drop(file);

            // Read-only mode is defense in depth; the protected store directory
            // prevents untrusted users from replacing or unlinking the object.
            set_read_only(&temporary).map_err(|error| ContentStoreError::Io {
                operation: "make object read-only",
                message: error.to_string(),
            })?;

            match fs::hard_link(&temporary, &destination) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    verify_existing(&destination, expected_sha256, total, max_bytes)?;
                }
                Err(error) => {
                    return Err(ContentStoreError::Io {
                        operation: "publish immutable object",
                        message: error.to_string(),
                    });
                }
            }

            File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| ContentStoreError::Io {
                    operation: "sync content-store directory",
                    message: error.to_string(),
                })?;

            Ok(StoredObject {
                sha256: expected_sha256.to_string(),
                size: total,
                path: destination.clone(),
            })
        })();

        // Always remove the temporary name. A successful publication has its
        // own hard link and is unaffected by this unlink.
        let _ = fs::remove_file(&temporary);
        result
    }

    /// Re-hash an existing object before another layer consumes it.
    pub fn verify_object(
        &self,
        expected_sha256: &str,
        max_bytes: u64,
    ) -> Result<StoredObject, ContentStoreError> {
        let path = self.path_for(expected_sha256)?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| ContentStoreError::Io {
            operation: "inspect stored object",
            message: error.to_string(),
        })?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(ContentStoreError::UnsafeObject);
        }
        if metadata.len() > max_bytes {
            return Err(ContentStoreError::ObjectTooLarge {
                size: metadata.len(),
                limit: max_bytes,
            });
        }

        let file = File::open(&path).map_err(|error| ContentStoreError::Io {
            operation: "open stored object",
            message: error.to_string(),
        })?;
        let (actual, size) = hash_reader(file, max_bytes)?;
        if actual != expected_sha256 {
            return Err(ContentStoreError::DigestMismatch {
                expected: expected_sha256.to_string(),
                actual,
            });
        }
        Ok(StoredObject {
            sha256: expected_sha256.to_string(),
            size,
            path,
        })
    }

    pub fn path_for(&self, sha256: &str) -> Result<PathBuf, ContentStoreError> {
        if !valid_digest(sha256) {
            return Err(ContentStoreError::InvalidDigest);
        }
        Ok(self.directory.join(format!("{sha256}.blob")))
    }

    fn create_temporary_file(&self) -> Result<(PathBuf, File), ContentStoreError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();

        for attempt in 0..MAX_TEMP_NAME_ATTEMPTS {
            let path = self.directory.join(format!(
                ".object.{}.{}.{}.tmp",
                std::process::id(),
                timestamp,
                attempt
            ));
            match open_private_new_file(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(ContentStoreError::Io {
                        operation: "reserve temporary object",
                        message: error.to_string(),
                    });
                }
            }
        }

        Err(ContentStoreError::Io {
            operation: "reserve temporary object",
            message: "too many temporary path collisions".into(),
        })
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_reader<R: Read>(
    mut reader: R,
    max_bytes: u64,
) -> Result<(String, u64), ContentStoreError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    let mut total = 0_u64;

    loop {
        let remaining = max_bytes.saturating_sub(total);
        let read_limit = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
        let read = loop {
            match reader.read(&mut buffer[..read_limit]) {
                Ok(read) => break read,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(ContentStoreError::Io {
                        operation: "read stored object",
                        message: error.to_string(),
                    });
                }
            }
        };
        if read == 0 {
            break;
        }

        total = total
            .checked_add(read as u64)
            .ok_or(ContentStoreError::ObjectTooLarge {
                size: u64::MAX,
                limit: max_bytes,
            })?;
        if total > max_bytes {
            return Err(ContentStoreError::ObjectTooLarge {
                size: total,
                limit: max_bytes,
            });
        }
        hasher.update(&buffer[..read]);
    }

    Ok((format!("{:x}", hasher.finalize()), total))
}

fn verify_existing(
    destination: &Path,
    expected_sha256: &str,
    expected_size: u64,
    max_bytes: u64,
) -> Result<(), ContentStoreError> {
    let metadata = fs::symlink_metadata(destination).map_err(|error| ContentStoreError::Io {
        operation: "inspect existing content-addressed object",
        message: error.to_string(),
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ContentStoreError::UnsafeObject);
    }
    if metadata.len() != expected_size || metadata.len() > max_bytes {
        return Err(ContentStoreError::CorruptExistingObject);
    }

    let file = File::open(destination).map_err(|error| ContentStoreError::Io {
        operation: "open existing content-addressed object",
        message: error.to_string(),
    })?;
    let (actual, actual_size) = hash_reader(file, max_bytes)?;
    if actual != expected_sha256 || actual_size != expected_size {
        return Err(ContentStoreError::CorruptExistingObject);
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_directory(metadata: &fs::Metadata) -> Result<(), ContentStoreError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(ContentStoreError::UnsafeDirectory);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_directory(_metadata: &fs::Metadata) -> Result<(), ContentStoreError> {
    Ok(())
}

fn open_private_new_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn set_read_only(path: &Path) -> std::io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let count = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "deku-content-store-{}-{count}",
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
            if let Ok(entries) = fs::read_dir(&self.0) {
                for entry in entries.flatten() {
                    let _ = fs::remove_file(entry.path());
                }
            }
            let _ = fs::remove_dir(&self.0);
        }
    }

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn stores_and_verifies_content_addressed_object() {
        let directory = TestDirectory::new();
        let store = ContentStore::open(&directory.0).expect("open store");
        let bytes = b"native artifact bytes";
        let expected = digest(bytes);

        let stored = store
            .put_reader(Cursor::new(bytes), &expected, 1024)
            .expect("store verified bytes");
        assert_eq!(stored.sha256, expected);
        assert_eq!(stored.size, bytes.len() as u64);
        assert_eq!(fs::read(&stored.path).expect("read stored object"), bytes);
        assert_eq!(
            store.verify_object(&expected, 1024).expect("verify object"),
            stored
        );
    }

    #[test]
    fn deduplicates_repeated_objects_without_overwriting() {
        let directory = TestDirectory::new();
        let store = ContentStore::open(&directory.0).expect("open store");
        let bytes = b"same content";
        let expected = digest(bytes);

        let first = store
            .put_reader(Cursor::new(bytes), &expected, 1024)
            .expect("store first");
        let second = store
            .put_reader(Cursor::new(bytes), &expected, 1024)
            .expect("deduplicate second");
        assert_eq!(first, second);
        assert_eq!(fs::read_dir(&directory.0).expect("list").count(), 1);
    }

    #[test]
    fn rejects_digest_mismatch_and_cleans_temporary_file() {
        let directory = TestDirectory::new();
        let store = ContentStore::open(&directory.0).expect("open store");
        let wrong = digest(b"expected");
        assert!(matches!(
            store.put_reader(Cursor::new(b"actual"), &wrong, 1024),
            Err(ContentStoreError::DigestMismatch { .. })
        ));
        assert_eq!(fs::read_dir(&directory.0).expect("list").count(), 0);
    }

    #[test]
    fn rejects_oversized_streams_and_invalid_digest_identifiers() {
        let directory = TestDirectory::new();
        let store = ContentStore::open(&directory.0).expect("open store");
        let bytes = b"long stream";
        assert!(matches!(
            store.put_reader(Cursor::new(bytes), &digest(bytes), 3),
            Err(ContentStoreError::ObjectTooLarge { .. })
        ));
        assert!(matches!(
            store.put_reader(Cursor::new(bytes), "ABC", 1024),
            Err(ContentStoreError::InvalidDigest)
        ));
        assert_eq!(fs::read_dir(&directory.0).expect("list").count(), 0);
    }

    #[test]
    fn detects_corrupted_existing_object() {
        let directory = TestDirectory::new();
        let store = ContentStore::open(&directory.0).expect("open store");
        let bytes = b"immutable candidate";
        let expected = digest(bytes);
        let stored = store
            .put_reader(Cursor::new(bytes), &expected, 1024)
            .expect("store object");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&stored.path, fs::Permissions::from_mode(0o600))
                .expect("make corruptible for test");
        }
        fs::write(&stored.path, b"tampered object").expect("tamper test object");
        assert!(matches!(
            store.verify_object(&expected, 1024),
            Err(ContentStoreError::DigestMismatch { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_world_writable_directory() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TestDirectory::new();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o770))
            .expect("make directory unsafe");
        assert!(matches!(
            ContentStore::open(&directory.0),
            Err(ContentStoreError::UnsafeDirectory)
        ));
    }
}
