//! Durable storage for the package transaction journal.
//!
//! This module persists only the small transaction state journal. It does not
//! install files, switch system generations, or claim that filesystem effects
//! match the recorded state. The caller must create a private directory owned
//! by the package manager and must reconcile file state during recovery.

use crate::{TransactionError, TransactionJournal};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_JOURNAL_BYTES: usize = 1024 * 1024;
const MAX_TEMP_NAME_ATTEMPTS: u32 = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalStoreError {
    InvalidTransactionId,
    UnsafeDirectory,
    UnsafeJournalFile,
    JournalTooLarge {
        size: usize,
        limit: usize,
    },
    InvalidJournal(String),
    Io {
        operation: &'static str,
        message: String,
    },
}

impl std::fmt::Display for JournalStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransactionId => write!(f, "invalid transaction identifier"),
            Self::UnsafeDirectory => write!(
                f,
                "journal directory must be an existing non-symlink directory not writable by group or others"
            ),
            Self::UnsafeJournalFile => {
                write!(f, "journal path must be a regular, non-symlink file")
            }
            Self::JournalTooLarge { size, limit } => {
                write!(f, "journal is {size} bytes; maximum is {limit}")
            }
            Self::InvalidJournal(message) => write!(f, "journal is invalid: {message}"),
            Self::Io { operation, message } => write!(f, "{operation} failed: {message}"),
        }
    }
}

impl std::error::Error for JournalStoreError {}

/// Storage adapter for journals in a pre-created package-manager state directory.
#[derive(Debug, Clone)]
pub struct TransactionJournalStore {
    directory: PathBuf,
}

impl TransactionJournalStore {
    /// Open an existing protected directory. This constructor does not create
    /// directories or change permissions; service setup must provision the path.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, JournalStoreError> {
        let path = directory.as_ref();
        let metadata = fs::symlink_metadata(path).map_err(|error| JournalStoreError::Io {
            operation: "inspect journal directory",
            message: error.to_string(),
        })?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(JournalStoreError::UnsafeDirectory);
        }
        ensure_private_directory(&metadata)?;
        let canonical = fs::canonicalize(path).map_err(|error| JournalStoreError::Io {
            operation: "canonicalize journal directory",
            message: error.to_string(),
        })?;
        Ok(Self {
            directory: canonical,
        })
    }

    /// Atomically replace a journal after validating it and durably syncing its
    /// new contents. A sync/rename error is returned; callers must reload state
    /// before assuming which copy is authoritative.
    pub fn save(&self, journal: &TransactionJournal) -> Result<PathBuf, JournalStoreError> {
        journal
            .validate()
            .map_err(|error| JournalStoreError::InvalidJournal(error.to_string()))?;
        let bytes = serde_json::to_vec(journal)
            .map_err(|error| JournalStoreError::InvalidJournal(error.to_string()))?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(JournalStoreError::JournalTooLarge {
                size: bytes.len(),
                limit: MAX_JOURNAL_BYTES,
            });
        }

        let destination = self.path_for(&journal.transaction_id)?;
        match fs::symlink_metadata(&destination) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    return Err(JournalStoreError::UnsafeJournalFile);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(JournalStoreError::Io {
                    operation: "inspect existing journal",
                    message: error.to_string(),
                });
            }
        }

        let (temporary, mut file) = self.create_temporary_file(journal)?;
        let write_result = (|| {
            file.write_all(&bytes)
                .map_err(|error| JournalStoreError::Io {
                    operation: "write temporary journal",
                    message: error.to_string(),
                })?;
            file.sync_all().map_err(|error| JournalStoreError::Io {
                operation: "sync temporary journal",
                message: error.to_string(),
            })?;
            drop(file);

            fs::rename(&temporary, &destination).map_err(|error| JournalStoreError::Io {
                operation: "atomically replace journal",
                message: error.to_string(),
            })?;
            File::open(&self.directory)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| JournalStoreError::Io {
                    operation: "sync journal directory",
                    message: error.to_string(),
                })?;
            Ok(destination.clone())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        write_result
    }

    /// Load and validate a journal, enforcing a byte limit before JSON parsing.
    /// File content is state evidence only; the caller still must compare it
    /// with the package database and filesystem before recovery.
    pub fn load(&self, transaction_id: &str) -> Result<TransactionJournal, JournalStoreError> {
        let path = self.path_for(transaction_id)?;
        let metadata = fs::symlink_metadata(&path).map_err(|error| JournalStoreError::Io {
            operation: "inspect journal",
            message: error.to_string(),
        })?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(JournalStoreError::UnsafeJournalFile);
        }
        if metadata.len() > MAX_JOURNAL_BYTES as u64 {
            return Err(JournalStoreError::JournalTooLarge {
                size: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
                limit: MAX_JOURNAL_BYTES,
            });
        }

        let file = File::open(&path).map_err(|error| JournalStoreError::Io {
            operation: "open journal",
            message: error.to_string(),
        })?;
        let mut bytes = Vec::new();
        file.take((MAX_JOURNAL_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| JournalStoreError::Io {
                operation: "read journal",
                message: error.to_string(),
            })?;
        if bytes.len() > MAX_JOURNAL_BYTES {
            return Err(JournalStoreError::JournalTooLarge {
                size: bytes.len(),
                limit: MAX_JOURNAL_BYTES,
            });
        }

        let journal =
            TransactionJournal::from_json(&bytes).map_err(|error: TransactionError| {
                JournalStoreError::InvalidJournal(error.to_string())
            })?;
        if journal.transaction_id != transaction_id {
            return Err(JournalStoreError::InvalidJournal(
                "transaction identifier does not match its file name".into(),
            ));
        }
        Ok(journal)
    }

    pub fn path_for(&self, transaction_id: &str) -> Result<PathBuf, JournalStoreError> {
        if !valid_id(transaction_id) {
            return Err(JournalStoreError::InvalidTransactionId);
        }
        Ok(self.directory.join(format!("{transaction_id}.json")))
    }

    fn create_temporary_file(
        &self,
        journal: &TransactionJournal,
    ) -> Result<(PathBuf, File), JournalStoreError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        for attempt in 0..MAX_TEMP_NAME_ATTEMPTS {
            let path = self.directory.join(format!(
                ".{}.{}.{}.{}.tmp",
                journal.transaction_id,
                std::process::id(),
                timestamp,
                attempt
            ));
            match open_private_new_file(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(JournalStoreError::Io {
                        operation: "reserve temporary journal path",
                        message: error.to_string(),
                    });
                }
            }
        }
        Err(JournalStoreError::Io {
            operation: "reserve temporary journal path",
            message: "too many temporary path collisions".into(),
        })
    }
}

fn valid_id(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

#[cfg(unix)]
fn ensure_private_directory(metadata: &fs::Metadata) -> Result<(), JournalStoreError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(JournalStoreError::UnsafeDirectory);
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_directory(_metadata: &fs::Metadata) -> Result<(), JournalStoreError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TransactionState;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let count = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("deku-journal-store-{}-{count}", std::process::id()));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn saves_and_loads_journal_after_each_transition() {
        let temp = TestDirectory::new();
        let store = TransactionJournalStore::open(&temp.0).unwrap();
        let mut journal = TransactionJournal::new("txn-store-001").unwrap();

        store.save(&journal).unwrap();
        journal
            .transition(TransactionState::Acquiring, None)
            .unwrap();
        store.save(&journal).unwrap();
        journal
            .transition(TransactionState::Verifying, None)
            .unwrap();
        store.save(&journal).unwrap();

        let loaded = store.load("txn-store-001").unwrap();
        assert_eq!(loaded, journal);
        assert_eq!(loaded.state, TransactionState::Verifying);
        assert_eq!(
            loaded.recovery_disposition(),
            crate::RecoveryDisposition::DiscardUncommittedStaging
        );
        assert!(!fs::read_dir(&temp.0).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn rejects_invalid_ids_and_directory_symlinks() {
        let temp = TestDirectory::new();
        let store = TransactionJournalStore::open(&temp.0).unwrap();
        assert!(matches!(
            store.path_for("../escape"),
            Err(JournalStoreError::InvalidTransactionId)
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = temp.0.with_extension("directory-link");
            symlink(&temp.0, &link).unwrap();
            assert!(matches!(
                TransactionJournalStore::open(&link),
                Err(JournalStoreError::UnsafeDirectory)
            ));
            fs::remove_file(link).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_world_writable_store_directory() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TestDirectory::new();
        fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            TransactionJournalStore::open(&temp.0),
            Err(JournalStoreError::UnsafeDirectory)
        ));
        fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_journal_file() {
        use std::os::unix::fs::symlink;
        let temp = TestDirectory::new();
        let store = TransactionJournalStore::open(&temp.0).unwrap();
        let journal = TransactionJournal::new("txn-store-002").unwrap();
        let path = store.save(&journal).unwrap();
        fs::remove_file(&path).unwrap();
        symlink(temp.0.join("some-other-file"), &path).unwrap();
        assert!(matches!(
            store.load("txn-store-002"),
            Err(JournalStoreError::UnsafeJournalFile)
        ));
    }

    #[test]
    fn rejects_journal_whose_id_does_not_match_file_name() {
        let temp = TestDirectory::new();
        let store = TransactionJournalStore::open(&temp.0).unwrap();
        let journal = TransactionJournal::new("txn-store-003").unwrap();
        store.save(&journal).unwrap();
        let bytes = serde_json::to_vec(&journal).unwrap();
        let other = temp.0.join("txn-store-004.json");
        fs::write(other, bytes).unwrap();
        assert!(matches!(
            store.load("txn-store-004"),
            Err(JournalStoreError::InvalidJournal(_))
        ));
    }
}
