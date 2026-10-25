//! Experimental, side-effect-free core for Deku package metadata.
//! This crate validates a bounded catalog and computes a deterministic dependency order.
//! It does not download, install, execute package scripts, or mutate the host.

pub mod content_store;
pub mod journal_store;
pub mod package_archive;
pub mod package_builder;
pub mod solver;
pub mod solver_catalog;
pub mod version;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_CATALOG_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_CATALOG_PACKAGES: usize = 4_096;
const MAX_PACKAGE_DEPENDENCIES: usize = 256;
const MAX_DEPENDENCY_DEPTH: usize = 512;
const MAX_PACKAGE_NAME_LEN: usize = 128;
const MAX_ARTIFACT_FILE_LEN: usize = 180;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema_version: u32,
    pub packages: Vec<Package>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub artifact: Artifact,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub file: String,
    pub sha256: String,
}

impl Artifact {
    /// Verify a stream of artifact bytes without buffering the whole package.
    ///
    /// `max_bytes` must come from the caller's download/storage policy. The
    /// verifier reads at most one 64 KiB chunk beyond neither the configured
    /// byte limit nor the bytes needed to prove that the artifact is oversized.
    pub fn verify_reader<R: std::io::Read>(
        &self,
        mut reader: R,
        max_bytes: u64,
    ) -> Result<u64, CatalogError> {
        if !valid_digest(&self.sha256) {
            return Err(CatalogError::InvalidDigest(self.file.clone()));
        }

        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut total = 0_u64;

        loop {
            // Read no more than the remaining allowance plus one byte. That
            // single extra byte is sufficient to prove that the stream is too large.
            let remaining = max_bytes.saturating_sub(total);
            let read_limit = remaining.saturating_add(1).min(buffer.len() as u64) as usize;
            let read = loop {
                match reader.read(&mut buffer[..read_limit]) {
                    Ok(read) => break read,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        return Err(CatalogError::ArtifactReadError {
                            file: self.file.clone(),
                            message: error.to_string(),
                        });
                    }
                }
            };
            if read == 0 {
                break;
            }

            let next_total =
                total
                    .checked_add(read as u64)
                    .ok_or_else(|| CatalogError::ArtifactTooLarge {
                        file: self.file.clone(),
                        size: u64::MAX,
                        limit: max_bytes,
                    })?;
            if next_total > max_bytes {
                return Err(CatalogError::ArtifactTooLarge {
                    file: self.file.clone(),
                    size: next_total,
                    limit: max_bytes,
                });
            }

            hasher.update(&buffer[..read]);
            total = next_total;
        }

        let actual = format!("{:x}", hasher.finalize());
        if actual != self.sha256 {
            return Err(CatalogError::ArtifactDigestMismatch {
                file: self.file.clone(),
                expected: self.sha256.clone(),
                actual,
            });
        }
        Ok(total)
    }

    /// Verify a byte slice against the canonical lowercase SHA-256 digest.
    pub fn verify_bytes(&self, bytes: &[u8]) -> Result<(), CatalogError> {
        self.verify_reader(std::io::Cursor::new(bytes), bytes.len() as u64)
            .map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    UnsupportedSchema,
    MetadataTooLarge {
        size: usize,
        limit: usize,
    },
    InvalidJson(String),
    TooManyPackages {
        count: usize,
        limit: usize,
    },
    TooManyDependencies {
        package: String,
        count: usize,
        limit: usize,
    },
    DependencyDepthExceeded {
        limit: usize,
    },
    InvalidPackageName(String),
    InvalidVersion(String),
    UnsupportedArchitecture(String),
    InvalidArtifactFile(String),
    InvalidDigest(String),
    ArtifactDigestMismatch {
        file: String,
        expected: String,
        actual: String,
    },
    ArtifactTooLarge {
        file: String,
        size: u64,
        limit: u64,
    },
    ArtifactReadError {
        file: String,
        message: String,
    },
    DuplicatePackage(String),
    DuplicateDependency {
        package: String,
        dependency: String,
    },
    SelfDependency(String),
    MissingDependency {
        package: String,
        dependency: String,
    },
    DependencyCycle(Vec<String>),
}

impl std::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CatalogError {}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PACKAGE_NAME_LEN
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._+-".contains(&b))
}

fn valid_version(value: &str) -> bool {
    crate::version::DekuVersion::parse(value).is_ok()
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_file(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ARTIFACT_FILE_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        && value != "."
        && value != ".."
}

impl Catalog {
    /// Parse and validate untrusted JSON with a byte limit enforced before deserialization.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.len() > MAX_CATALOG_JSON_BYTES {
            return Err(CatalogError::MetadataTooLarge {
                size: bytes.len(),
                limit: MAX_CATALOG_JSON_BYTES,
            });
        }

        let catalog: Self = serde_json::from_slice(bytes)
            .map_err(|error| CatalogError::InvalidJson(error.to_string()))?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Validate parsed metadata before trusting it as input to a planner.
    ///
    /// This method assumes deserialization already happened. For untrusted JSON,
    /// use from_json() so the raw byte limit applies before parser allocation.
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.schema_version != 1 {
            return Err(CatalogError::UnsupportedSchema);
        }
        if self.packages.len() > MAX_CATALOG_PACKAGES {
            return Err(CatalogError::TooManyPackages {
                count: self.packages.len(),
                limit: MAX_CATALOG_PACKAGES,
            });
        }

        let mut by_name = BTreeMap::new();
        for package in &self.packages {
            if !valid_name(&package.name) {
                return Err(CatalogError::InvalidPackageName(package.name.clone()));
            }
            if !valid_version(&package.version) {
                return Err(CatalogError::InvalidVersion(package.name.clone()));
            }
            if !matches!(
                package.architecture.as_str(),
                "x86_64" | "aarch64" | "noarch"
            ) {
                return Err(CatalogError::UnsupportedArchitecture(
                    package.architecture.clone(),
                ));
            }
            if !valid_file(&package.artifact.file) {
                return Err(CatalogError::InvalidArtifactFile(
                    package.artifact.file.clone(),
                ));
            }
            if !valid_digest(&package.artifact.sha256) {
                return Err(CatalogError::InvalidDigest(package.name.clone()));
            }
            if package.dependencies.len() > MAX_PACKAGE_DEPENDENCIES {
                return Err(CatalogError::TooManyDependencies {
                    package: package.name.clone(),
                    count: package.dependencies.len(),
                    limit: MAX_PACKAGE_DEPENDENCIES,
                });
            }
            if by_name.insert(package.name.as_str(), package).is_some() {
                return Err(CatalogError::DuplicatePackage(package.name.clone()));
            }

            let mut dependencies = BTreeSet::new();
            for dependency in &package.dependencies {
                if !valid_name(dependency) {
                    return Err(CatalogError::InvalidPackageName(dependency.clone()));
                }
                if !dependencies.insert(dependency) {
                    return Err(CatalogError::DuplicateDependency {
                        package: package.name.clone(),
                        dependency: dependency.clone(),
                    });
                }
                if dependency == &package.name {
                    return Err(CatalogError::SelfDependency(package.name.clone()));
                }
            }
        }

        for package in &self.packages {
            for dependency in &package.dependencies {
                if !by_name.contains_key(dependency.as_str()) {
                    return Err(CatalogError::MissingDependency {
                        package: package.name.clone(),
                        dependency: dependency.clone(),
                    });
                }
            }
        }
        self.install_order().map(|_| ())
    }

    /// Return a deterministic dependency-first order; ties are sorted by package name.
    pub fn install_order(&self) -> Result<Vec<String>, CatalogError> {
        if self.packages.len() > MAX_CATALOG_PACKAGES {
            return Err(CatalogError::TooManyPackages {
                count: self.packages.len(),
                limit: MAX_CATALOG_PACKAGES,
            });
        }

        let mut packages = BTreeMap::<&str, &Package>::new();
        for package in &self.packages {
            if package.dependencies.len() > MAX_PACKAGE_DEPENDENCIES {
                return Err(CatalogError::TooManyDependencies {
                    package: package.name.clone(),
                    count: package.dependencies.len(),
                    limit: MAX_PACKAGE_DEPENDENCIES,
                });
            }
            if packages.insert(package.name.as_str(), package).is_some() {
                return Err(CatalogError::DuplicatePackage(package.name.clone()));
            }
        }

        let mut temporary = BTreeSet::<String>::new();
        let mut permanent = BTreeSet::<String>::new();
        let mut result = Vec::with_capacity(packages.len());
        let mut stack = Vec::<String>::new();

        fn visit<'a>(
            name: &'a str,
            packages: &BTreeMap<&'a str, &'a Package>,
            temporary: &mut BTreeSet<String>,
            permanent: &mut BTreeSet<String>,
            stack: &mut Vec<String>,
            result: &mut Vec<String>,
        ) -> Result<(), CatalogError> {
            if permanent.contains(name) {
                return Ok(());
            }
            if temporary.contains(name) {
                let start = stack.iter().position(|item| item == name).unwrap_or(0);
                let mut cycle = stack[start..].to_vec();
                cycle.push(name.to_string());
                return Err(CatalogError::DependencyCycle(cycle));
            }
            if stack.len() >= MAX_DEPENDENCY_DEPTH {
                return Err(CatalogError::DependencyDepthExceeded {
                    limit: MAX_DEPENDENCY_DEPTH,
                });
            }

            let package = packages
                .get(name)
                .ok_or_else(|| CatalogError::MissingDependency {
                    package: stack.last().cloned().unwrap_or_default(),
                    dependency: name.to_string(),
                })?;
            temporary.insert(name.to_string());
            stack.push(name.to_string());

            let mut deps = package.dependencies.clone();
            deps.sort();
            for dep in deps {
                visit(&dep, packages, temporary, permanent, stack, result)?;
            }

            stack.pop();
            temporary.remove(name);
            permanent.insert(name.to_string());
            result.push(name.to_string());
            Ok(())
        }

        for name in packages.keys() {
            visit(
                name,
                &packages,
                &mut temporary,
                &mut permanent,
                &mut stack,
                &mut result,
            )?;
        }
        Ok(result)
    }
}

const MAX_TRANSACTION_JOURNAL_BYTES: usize = 1_048_576;
const MAX_TRANSACTION_HISTORY: usize = 32;
const MAX_TRANSACTION_NOTE_BYTES: usize = 512;

/// Durable package-operation state. This type records intent and recovery
/// requirements; it does not perform filesystem or package operations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionState {
    Planned,
    Acquiring,
    Verifying,
    Staging,
    ReadyToCommit,
    Committing,
    Committed,
    RollingBack,
    RolledBack,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransactionEvent {
    pub sequence: u64,
    pub from: Option<TransactionState>,
    pub to: TransactionState,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransactionJournal {
    pub schema_version: u32,
    pub transaction_id: String,
    pub state: TransactionState,
    pub history: Vec<TransactionEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDisposition {
    /// The transaction is finished; do not mutate the filesystem for recovery.
    NoRecoveryRequired,
    /// The operation never entered the commit window; staged work can be
    /// discarded by a future transaction executor.
    DiscardUncommittedStaging,
    /// Filesystem effects may be partial. Reconcile the transaction journal
    /// with actual file state before any automatic action.
    ReconcileFilesystemBeforeContinuing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionError {
    InvalidTransactionId,
    UnsupportedSchema,
    JournalTooLarge {
        size: usize,
        limit: usize,
    },
    InvalidJson(String),
    InvalidHistory,
    InvalidTransition {
        from: TransactionState,
        to: TransactionState,
    },
    HistoryLimitExceeded {
        limit: usize,
    },
    InvalidNote,
}

impl std::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for TransactionError {}

fn valid_transaction_id(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_transaction_note(note: &str) -> bool {
    note.len() <= MAX_TRANSACTION_NOTE_BYTES
        && !note.is_empty()
        && !note.chars().any(char::is_control)
}

fn transition_allowed(from: TransactionState, to: TransactionState) -> bool {
    use TransactionState::*;
    match from {
        Planned => matches!(to, Acquiring | Failed),
        Acquiring => matches!(to, Verifying | Failed),
        Verifying => matches!(to, Staging | Failed),
        Staging => matches!(to, ReadyToCommit | Failed),
        ReadyToCommit => matches!(to, Committing | RollingBack | Failed),
        Committing => matches!(to, Committed | RollingBack | Failed),
        RollingBack => matches!(to, RolledBack | Failed),
        Committed | RolledBack | Failed => false,
    }
}

impl TransactionJournal {
    /// Create a new plan-only journal. The identifier is caller-supplied so
    /// callers can choose a cryptographically random identifier without this
    /// pure core needing a random-number dependency.
    pub fn new(transaction_id: impl Into<String>) -> Result<Self, TransactionError> {
        let transaction_id = transaction_id.into();
        if !valid_transaction_id(&transaction_id) {
            return Err(TransactionError::InvalidTransactionId);
        }
        Ok(Self {
            schema_version: 1,
            transaction_id,
            state: TransactionState::Planned,
            history: vec![TransactionEvent {
                sequence: 0,
                from: None,
                to: TransactionState::Planned,
                note: None,
            }],
        })
    }

    /// Record one legal transition. No installation or rollback action is
    /// executed by this method.
    pub fn transition(
        &mut self,
        next: TransactionState,
        note: Option<String>,
    ) -> Result<(), TransactionError> {
        if self.schema_version != 1 {
            return Err(TransactionError::UnsupportedSchema);
        }
        self.validate()?;
        if let Some(value) = note.as_deref()
            && !valid_transaction_note(value)
        {
            return Err(TransactionError::InvalidNote);
        }
        if !transition_allowed(self.state, next) {
            return Err(TransactionError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        if self.history.len() >= MAX_TRANSACTION_HISTORY {
            return Err(TransactionError::HistoryLimitExceeded {
                limit: MAX_TRANSACTION_HISTORY,
            });
        }
        let sequence = self.history.len() as u64;
        let previous = self.state;
        self.history.push(TransactionEvent {
            sequence,
            from: Some(previous),
            to: next,
            note,
        });
        self.state = next;
        Ok(())
    }

    /// Validate the complete journal after deserialization or before writing.
    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.schema_version != 1 {
            return Err(TransactionError::UnsupportedSchema);
        }
        if !valid_transaction_id(&self.transaction_id)
            || self.history.is_empty()
            || self.history.len() > MAX_TRANSACTION_HISTORY
        {
            return Err(TransactionError::InvalidHistory);
        }
        let first = &self.history[0];
        if first.sequence != 0
            || first.from.is_some()
            || first.to != TransactionState::Planned
            || first.note.is_some()
        {
            return Err(TransactionError::InvalidHistory);
        }
        for (index, event) in self.history.iter().enumerate().skip(1) {
            let previous = &self.history[index - 1];
            if event.sequence != index as u64
                || event.from != Some(previous.to)
                || !transition_allowed(previous.to, event.to)
                || event
                    .note
                    .as_deref()
                    .is_some_and(|note| !valid_transaction_note(note))
            {
                return Err(TransactionError::InvalidHistory);
            }
        }
        if self.state
            != self
                .history
                .last()
                .ok_or(TransactionError::InvalidHistory)?
                .to
        {
            return Err(TransactionError::InvalidHistory);
        }
        Ok(())
    }

    /// Parse a bounded journal and re-check every state transition. A local
    /// journal is not signed metadata and must not be treated as proof that
    /// the filesystem actually reached the recorded state.
    pub fn from_json(bytes: &[u8]) -> Result<Self, TransactionError> {
        if bytes.len() > MAX_TRANSACTION_JOURNAL_BYTES {
            return Err(TransactionError::JournalTooLarge {
                size: bytes.len(),
                limit: MAX_TRANSACTION_JOURNAL_BYTES,
            });
        }
        let journal: Self = serde_json::from_slice(bytes)
            .map_err(|error| TransactionError::InvalidJson(error.to_string()))?;
        journal.validate()?;
        Ok(journal)
    }

    /// Return a conservative recovery classification. In the commit window,
    /// callers must compare the journal with actual installed files and package
    /// ownership state; never infer completion from journal text alone.
    pub fn recovery_disposition(&self) -> RecoveryDisposition {
        use TransactionState::*;
        match self.state {
            Committed | RolledBack => RecoveryDisposition::NoRecoveryRequired,
            Planned | Acquiring | Verifying | Staging | ReadyToCommit => {
                RecoveryDisposition::DiscardUncommittedStaging
            }
            Committing | RollingBack | Failed => {
                RecoveryDisposition::ReconcileFilesystemBeforeContinuing
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, deps: &[&str]) -> Package {
        Package {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            architecture: "x86_64".to_string(),
            artifact: Artifact {
                file: format!("{name}-1.0.0.tar.zst"),
                sha256: "a".repeat(64),
            },
            dependencies: deps.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn deterministic_dependency_first_order() {
        let catalog = Catalog {
            schema_version: 1,
            packages: vec![pkg("app", &["lib"]), pkg("lib", &[])],
        };
        assert_eq!(catalog.validate(), Ok(()));
        assert_eq!(catalog.install_order().unwrap(), vec!["lib", "app"]);
    }

    #[test]
    fn input_order_does_not_change_plan() {
        let forward = Catalog {
            schema_version: 1,
            packages: vec![pkg("app", &["lib"]), pkg("lib", &[])],
        };
        let reversed = Catalog {
            schema_version: 1,
            packages: vec![pkg("lib", &[]), pkg("app", &["lib"])],
        };
        assert_eq!(forward.install_order(), reversed.install_order());
    }

    #[test]
    fn bounded_json_parser_accepts_a_valid_empty_catalog() {
        let result = Catalog::from_json(br#"{"schema_version":1,"packages":[]}"#);
        assert_eq!(
            result,
            Ok(Catalog {
                schema_version: 1,
                packages: vec![],
            })
        );
    }

    #[test]
    fn bounded_json_parser_validates_deserialized_metadata() {
        let json = br#"{"schema_version":2,"packages":[]}"#;
        assert!(matches!(
            Catalog::from_json(json),
            Err(CatalogError::UnsupportedSchema)
        ));
    }

    #[test]
    fn invalid_json_is_rejected_by_bounded_parser() {
        assert!(matches!(
            Catalog::from_json(b"{not-json"),
            Err(CatalogError::InvalidJson(_))
        ));
    }

    #[test]
    fn oversized_json_is_rejected_before_deserialization() {
        let oversized = vec![b' '; MAX_CATALOG_JSON_BYTES + 1];
        assert!(matches!(
            Catalog::from_json(&oversized),
            Err(CatalogError::MetadataTooLarge {
                size,
                limit: MAX_CATALOG_JSON_BYTES
            }) if size == MAX_CATALOG_JSON_BYTES + 1
        ));
    }

    #[test]
    fn duplicate_struct_fields_are_rejected_by_json_parser() {
        let json = br#"{"schema_version":1,"schema_version":2,"packages":[]}"#;
        assert!(matches!(
            Catalog::from_json(json),
            Err(CatalogError::InvalidJson(_))
        ));
    }

    #[test]
    fn unknown_json_fields_are_rejected() {
        let json = r#"{"schema_version":1,"packages":[],"run":"arbitrary shell"}"#;
        assert!(serde_json::from_str::<Catalog>(json).is_err());
    }

    #[test]
    fn unknown_nested_fields_are_rejected() {
        let json = format!(
            r#"{{"schema_version":1,"packages":[{{"name":"app","version":"1.0.0","architecture":"x86_64","artifact":{{"file":"app.tar.zst","sha256":"{}","execute":true}}}}]}}"#,
            "a".repeat(64)
        );
        assert!(serde_json::from_str::<Catalog>(&json).is_err());
    }

    #[test]
    fn unsupported_schema_is_rejected() {
        let catalog = Catalog {
            schema_version: 2,
            packages: vec![],
        };
        assert_eq!(catalog.validate(), Err(CatalogError::UnsupportedSchema));
    }

    #[test]
    fn duplicate_packages_are_rejected() {
        let catalog = Catalog {
            schema_version: 1,
            packages: vec![pkg("lib", &[]), pkg("lib", &[])],
        };
        assert!(matches!(
            catalog.validate(),
            Err(CatalogError::DuplicatePackage(_))
        ));
    }

    #[test]
    fn invalid_package_identifiers_are_rejected() {
        for name in [
            "Uppercase",
            "1starts-with-digit",
            "name with spaces",
            "../escape",
        ] {
            let catalog = Catalog {
                schema_version: 1,
                packages: vec![pkg(name, &[])],
            };
            assert!(matches!(
                catalog.validate(),
                Err(CatalogError::InvalidPackageName(_))
            ));
        }
    }

    #[test]
    fn invalid_version_tokens_are_rejected() {
        for version in ["", " 1.0.0", "1.0.0 ", "1.0\n0", "../1.0.0"] {
            let mut package = pkg("app", &[]);
            package.version = version.to_string();
            let catalog = Catalog {
                schema_version: 1,
                packages: vec![package],
            };
            assert!(matches!(
                catalog.validate(),
                Err(CatalogError::InvalidVersion(_))
            ));
        }
    }

    #[test]
    fn unsupported_architecture_is_rejected() {
        let mut package = pkg("app", &[]);
        package.architecture = "unknown-arch".into();
        let catalog = Catalog {
            schema_version: 1,
            packages: vec![package],
        };
        assert!(matches!(
            catalog.validate(),
            Err(CatalogError::UnsupportedArchitecture(_))
        ));
    }

    #[test]
    fn duplicate_dependencies_are_rejected() {
        let catalog = Catalog {
            schema_version: 1,
            packages: vec![pkg("app", &["lib", "lib"]), pkg("lib", &[])],
        };
        assert!(matches!(
            catalog.validate(),
            Err(CatalogError::DuplicateDependency { .. })
        ));
    }

    #[test]
    fn missing_dependency_is_rejected() {
        let catalog = Catalog {
            schema_version: 1,
            packages: vec![pkg("app", &["missing"])],
        };
        assert!(matches!(
            catalog.validate(),
            Err(CatalogError::MissingDependency { .. })
        ));
    }

    #[test]
    fn dependency_cycle_is_rejected() {
        let catalog = Catalog {
            schema_version: 1,
            packages: vec![pkg("app", &["lib"]), pkg("lib", &["app"])],
        };
        assert!(matches!(
            catalog.validate(),
            Err(CatalogError::DependencyCycle(_))
        ));
    }

    #[test]
    fn dependency_depth_is_bounded() {
        let mut packages = Vec::new();
        for index in 0..=MAX_DEPENDENCY_DEPTH {
            let name = format!("p{index:04}");
            let dependencies = if index < MAX_DEPENDENCY_DEPTH {
                vec![format!("p{:04}", index + 1)]
            } else {
                vec![]
            };
            packages.push(Package {
                name,
                version: "1.0.0".into(),
                architecture: "x86_64".into(),
                artifact: Artifact {
                    file: format!("p{index:04}.tar.zst"),
                    sha256: "a".repeat(64),
                },
                dependencies,
            });
        }
        let catalog = Catalog {
            schema_version: 1,
            packages,
        };
        assert!(matches!(
            catalog.validate(),
            Err(CatalogError::DependencyDepthExceeded { .. })
        ));
    }

    #[test]
    fn artifact_bytes_are_verified_against_sha256() {
        let artifact = Artifact {
            file: "app.tar.zst".into(),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        };
        assert_eq!(artifact.verify_bytes(b"abc"), Ok(()));
        assert!(matches!(
            artifact.verify_bytes(b"tampered"),
            Err(CatalogError::ArtifactDigestMismatch { .. })
        ));
    }

    #[test]
    fn streaming_verifier_accepts_valid_bytes_within_limit() {
        let artifact = Artifact {
            file: "app.tar.zst".into(),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        };
        assert_eq!(
            artifact.verify_reader(std::io::Cursor::new(b"abc"), 3),
            Ok(3)
        );
    }

    #[test]
    fn streaming_verifier_rejects_artifact_over_size_limit() {
        let artifact = Artifact {
            file: "app.tar.zst".into(),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        };
        assert!(matches!(
            artifact.verify_reader(std::io::Cursor::new(b"abc"), 2),
            Err(CatalogError::ArtifactTooLarge {
                file,
                size: 3,
                limit: 2
            }) if file == "app.tar.zst"
        ));
    }

    #[test]
    fn streaming_verifier_reads_at_most_one_byte_past_limit() {
        let artifact = Artifact {
            file: "large.tar.zst".into(),
            sha256: "a".repeat(64),
        };
        let data = vec![b'x'; 100_000];
        let mut reader = std::io::Cursor::new(data);
        assert!(matches!(
            artifact.verify_reader(&mut reader, 2),
            Err(CatalogError::ArtifactTooLarge {
                size: 3,
                limit: 2,
                ..
            })
        ));
        assert_eq!(reader.position(), 3);
    }

    #[test]
    fn streaming_verifier_reports_reader_errors() {
        struct BrokenReader;

        impl std::io::Read for BrokenReader {
            fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("fixture read error"))
            }
        }

        let artifact = Artifact {
            file: "app.tar.zst".into(),
            sha256: "a".repeat(64),
        };
        assert!(matches!(
            artifact.verify_reader(BrokenReader, 1024),
            Err(CatalogError::ArtifactReadError { .. })
        ));
    }

    #[test]
    fn streaming_verifier_retries_interrupted_reads() {
        struct InterruptOnce {
            interrupted: bool,
            bytes: std::io::Cursor<Vec<u8>>,
        }

        impl std::io::Read for InterruptOnce {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;
                    return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
                }
                std::io::Read::read(&mut self.bytes, buffer)
            }
        }

        let artifact = Artifact {
            file: "app.tar.zst".into(),
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        };
        let reader = InterruptOnce {
            interrupted: false,
            bytes: std::io::Cursor::new(b"abc".to_vec()),
        };

        assert_eq!(artifact.verify_reader(reader, 3), Ok(3));
    }

    #[test]
    fn streaming_verifier_accepts_empty_artifact_only_with_empty_digest() {
        let artifact = Artifact {
            file: "empty.tar.zst".into(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        };
        assert_eq!(
            artifact.verify_reader(std::io::Cursor::new(Vec::<u8>::new()), 0),
            Ok(0)
        );

        let bad = Artifact {
            file: "empty.tar.zst".into(),
            sha256: "a".repeat(64),
        };
        assert!(matches!(
            bad.verify_reader(std::io::Cursor::new([]), 0),
            Err(CatalogError::ArtifactDigestMismatch { .. })
        ));
    }

    #[test]
    fn streaming_verifier_checks_digest_after_reading() {
        let artifact = Artifact {
            file: "app.tar.zst".into(),
            sha256: "a".repeat(64),
        };
        assert!(matches!(
            artifact.verify_reader(std::io::Cursor::new(b"abc"), 3),
            Err(CatalogError::ArtifactDigestMismatch { .. })
        ));
    }

    #[test]
    fn malformed_digest_is_rejected() {
        let mut package = pkg("app", &[]);
        package.artifact.sha256 = "not-a-digest".into();
        let catalog = Catalog {
            schema_version: 1,
            packages: vec![package],
        };
        assert!(matches!(
            catalog.validate(),
            Err(CatalogError::InvalidDigest(_))
        ));
    }

    #[test]
    fn uppercase_digest_is_rejected_as_noncanonical() {
        let mut package = pkg("app", &[]);
        package.artifact.sha256 = "A".repeat(64);
        let catalog = Catalog {
            schema_version: 1,
            packages: vec![package],
        };
        assert!(matches!(
            catalog.validate(),
            Err(CatalogError::InvalidDigest(_))
        ));
    }

    #[test]
    fn path_traversal_artifact_filename_is_rejected() {
        for file in ["../payload", "/tmp/payload", r"..\payload"] {
            let mut package = pkg("app", &[]);
            package.artifact.file = file.into();
            let catalog = Catalog {
                schema_version: 1,
                packages: vec![package],
            };
            assert!(matches!(
                catalog.validate(),
                Err(CatalogError::InvalidArtifactFile(_))
            ));
        }
    }

    #[test]
    fn transaction_journal_records_a_valid_commit_path() {
        let mut journal = TransactionJournal::new("txn-0001").unwrap();
        journal
            .transition(TransactionState::Acquiring, None)
            .unwrap();
        journal
            .transition(TransactionState::Verifying, None)
            .unwrap();
        journal.transition(TransactionState::Staging, None).unwrap();
        journal
            .transition(TransactionState::ReadyToCommit, None)
            .unwrap();
        journal
            .transition(TransactionState::Committing, None)
            .unwrap();
        journal
            .transition(TransactionState::Committed, Some("files verified".into()))
            .unwrap();
        assert_eq!(journal.validate(), Ok(()));
        assert_eq!(
            journal.recovery_disposition(),
            RecoveryDisposition::NoRecoveryRequired
        );
    }

    #[test]
    fn transaction_journal_rejects_skipping_verification() {
        let mut journal = TransactionJournal::new("txn-0002").unwrap();
        assert!(matches!(
            journal.transition(TransactionState::Committing, None),
            Err(TransactionError::InvalidTransition {
                from: TransactionState::Planned,
                to: TransactionState::Committing
            })
        ));
        assert_eq!(journal.state, TransactionState::Planned);
    }

    #[test]
    fn transaction_journal_rejects_transitions_after_commit() {
        let mut journal = TransactionJournal::new("txn-0003").unwrap();
        journal.transition(TransactionState::Failed, None).unwrap();
        assert!(matches!(
            journal.transition(TransactionState::Committed, None),
            Err(TransactionError::InvalidTransition {
                from: TransactionState::Failed,
                to: TransactionState::Committed
            })
        ));
    }

    #[test]
    fn transaction_journal_rejects_invalid_ids_and_notes() {
        assert!(matches!(
            TransactionJournal::new("../unsafe"),
            Err(TransactionError::InvalidTransactionId)
        ));
        let mut journal = TransactionJournal::new("txn-0004").unwrap();
        assert!(matches!(
            journal.transition(TransactionState::Failed, Some("bad\nmessage".into())),
            Err(TransactionError::InvalidNote)
        ));
    }

    #[test]
    fn transaction_journal_round_trips_and_validates_history() {
        let mut journal = TransactionJournal::new("txn-0005").unwrap();
        journal
            .transition(TransactionState::Failed, Some("verification failed".into()))
            .unwrap();
        let bytes = serde_json::to_vec(&journal).unwrap();
        assert_eq!(TransactionJournal::from_json(&bytes), Ok(journal));

        let mut inconsistent =
            serde_json::to_value(TransactionJournal::new("txn-0006").unwrap()).unwrap();
        inconsistent["state"] = serde_json::to_value(TransactionState::Committed).unwrap();
        let bytes = serde_json::to_vec(&inconsistent).unwrap();
        assert_eq!(
            TransactionJournal::from_json(&bytes),
            Err(TransactionError::InvalidHistory)
        );
    }

    #[test]
    fn transaction_journal_fails_closed_on_unknown_fields_and_oversize() {
        assert!(matches!(
            TransactionJournal::from_json(br#"{"schema_version":1,"transaction_id":"txn-0007","state":"planned","history":[],"execute":"true"}"#),
            Err(TransactionError::InvalidJson(_))
        ));
        let oversized = vec![b' '; MAX_TRANSACTION_JOURNAL_BYTES + 1];
        assert!(matches!(
            TransactionJournal::from_json(&oversized),
            Err(TransactionError::JournalTooLarge { .. })
        ));
    }

    #[test]
    fn transaction_journal_treats_commit_window_as_reconciliation_only() {
        let mut journal = TransactionJournal::new("txn-0008").unwrap();
        journal
            .transition(TransactionState::Acquiring, None)
            .unwrap();
        journal
            .transition(TransactionState::Verifying, None)
            .unwrap();
        journal.transition(TransactionState::Staging, None).unwrap();
        journal
            .transition(TransactionState::ReadyToCommit, None)
            .unwrap();
        journal
            .transition(TransactionState::Committing, None)
            .unwrap();
        assert_eq!(
            journal.recovery_disposition(),
            RecoveryDisposition::ReconcileFilesystemBeforeContinuing
        );
    }
}
