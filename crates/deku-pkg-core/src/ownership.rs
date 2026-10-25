//! Installed-package metadata and a pure filesystem ownership/conflict index.
//!
//! This module is a preflight primitive, not an installer. It validates the
//! on-disk package database schema in memory, indexes each installed path, and
//! checks a prospective package archive against installed ownership before any
//! future transaction executor is allowed to stage or activate it.

use crate::package_archive::{
    ArchiveError, PackageArchiveManifest, PackageFile, PackageFileKind, PackageInfo,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_INSTALLED_DATABASE_BYTES: usize = 64 * 1024 * 1024;
const MAX_INSTALLED_PACKAGES: usize = 65_536;
const MAX_INSTALLED_FILES: usize = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledDatabase {
    pub schema_version: u32,
    /// Monotonically increasing system generation, managed by the future transaction layer.
    pub generation: u64,
    /// Canonically sorted by package name; only one installed version per name.
    pub packages: Vec<InstalledPackageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledPackageRecord {
    pub package: PackageInfo,
    /// The verified archive manifest for the currently installed package.
    pub files: Vec<PackageFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedPath {
    pub entry: PackageFile,
    /// Multiple packages may share an explicit directory only when its mode agrees.
    pub owners: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileOwnershipIndex {
    paths: BTreeMap<String, OwnedPath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOwnershipAssessment {
    pub package_name: String,
    pub database_generation: u64,
    pub replacing_existing_version: bool,
    /// Paths that will be owned by the prospective package and are not shared directories.
    /// This is metadata only; it does not claim that the paths have been written.
    pub paths_to_claim: Vec<String>,
    /// Directories already owned by another package with the same mode.
    pub shared_directories: Vec<String>,
    /// Paths from the previous version whose ownership is no longer present in the new manifest.
    /// Removal must still wait until the transaction executor proves no remaining owner/child needs them.
    pub paths_to_release: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnershipError {
    MetadataTooLarge {
        size: usize,
        limit: usize,
    },
    InvalidJson(String),
    UnsupportedSchema,
    TooManyPackages {
        count: usize,
        limit: usize,
    },
    TooManyFiles {
        count: usize,
        limit: usize,
    },
    DuplicatePackage(String),
    UnsortedPackages,
    InvalidPackageManifest {
        package: String,
        reason: String,
    },
    FileAlreadyOwned {
        path: String,
        first_package: String,
        second_package: String,
    },
    PathTypeConflict {
        path: String,
        first_package: String,
        second_package: String,
    },
    DirectoryModeConflict {
        path: String,
        first_mode: u32,
        second_mode: u32,
    },
    FileParentConflict {
        file: String,
        descendant: String,
    },
}

impl std::fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for OwnershipError {}

impl InstalledPackageRecord {
    pub fn from_manifest(manifest: &PackageArchiveManifest) -> Self {
        Self {
            package: manifest.package.clone(),
            files: manifest.files.clone(),
        }
    }

    fn as_manifest(&self) -> PackageArchiveManifest {
        PackageArchiveManifest {
            schema_version: 1,
            package: self.package.clone(),
            files: self.files.clone(),
        }
    }
}

impl InstalledDatabase {
    pub fn empty() -> Self {
        Self {
            schema_version: 1,
            generation: 0,
            packages: Vec::new(),
        }
    }

    pub fn from_manifests(
        generation: u64,
        manifests: impl IntoIterator<Item = PackageArchiveManifest>,
    ) -> Result<Self, OwnershipError> {
        let mut packages = manifests
            .into_iter()
            .map(|manifest| InstalledPackageRecord::from_manifest(&manifest))
            .collect::<Vec<_>>();
        packages.sort_by(|left, right| left.package.name.cmp(&right.package.name));
        let database = Self {
            schema_version: 1,
            generation,
            packages,
        };
        database.validate()?;
        Ok(database)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, OwnershipError> {
        if bytes.len() > MAX_INSTALLED_DATABASE_BYTES {
            return Err(OwnershipError::MetadataTooLarge {
                size: bytes.len(),
                limit: MAX_INSTALLED_DATABASE_BYTES,
            });
        }
        let database: Self = serde_json::from_slice(bytes)
            .map_err(|error| OwnershipError::InvalidJson(error.to_string()))?;
        database.validate()?;
        Ok(database)
    }

    pub fn to_json(&self) -> Result<Vec<u8>, OwnershipError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| OwnershipError::InvalidJson(error.to_string()))?;
        if bytes.len() > MAX_INSTALLED_DATABASE_BYTES {
            return Err(OwnershipError::MetadataTooLarge {
                size: bytes.len(),
                limit: MAX_INSTALLED_DATABASE_BYTES,
            });
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), OwnershipError> {
        self.validate_structure()?;
        build_index(&self.packages).map(|_| ())
    }

    fn validate_structure(&self) -> Result<(), OwnershipError> {
        if self.schema_version != 1 {
            return Err(OwnershipError::UnsupportedSchema);
        }
        if self.packages.len() > MAX_INSTALLED_PACKAGES {
            return Err(OwnershipError::TooManyPackages {
                count: self.packages.len(),
                limit: MAX_INSTALLED_PACKAGES,
            });
        }

        let mut total_files = 0usize;
        let mut previous_name: Option<&str> = None;
        for record in &self.packages {
            if let Some(previous) = previous_name {
                if previous == record.package.name.as_str() {
                    return Err(OwnershipError::DuplicatePackage(
                        record.package.name.clone(),
                    ));
                }
                if previous > record.package.name.as_str() {
                    return Err(OwnershipError::UnsortedPackages);
                }
            }
            previous_name = Some(&record.package.name);

            total_files = total_files.checked_add(record.files.len()).ok_or(
                OwnershipError::TooManyFiles {
                    count: usize::MAX,
                    limit: MAX_INSTALLED_FILES,
                },
            )?;
            if total_files > MAX_INSTALLED_FILES {
                return Err(OwnershipError::TooManyFiles {
                    count: total_files,
                    limit: MAX_INSTALLED_FILES,
                });
            }

            record
                .as_manifest()
                .validate()
                .map_err(
                    |error: ArchiveError| OwnershipError::InvalidPackageManifest {
                        package: record.package.name.clone(),
                        reason: error.to_string(),
                    },
                )?;
        }
        Ok(())
    }

    pub fn ownership_index(&self) -> Result<FileOwnershipIndex, OwnershipError> {
        self.validate_structure()?;
        build_index(&self.packages)
    }

    /// Preflight installation/upgrade without touching the filesystem.
    ///
    /// The existing version of the same package is removed from the comparison
    /// set first, so an upgrade may replace its own paths. Paths owned by other
    /// packages still enforce strict collision and directory-mode rules.
    pub fn assess_install(
        &self,
        incoming: &PackageArchiveManifest,
    ) -> Result<InstallOwnershipAssessment, OwnershipError> {
        self.validate_structure()?;
        incoming
            .validate()
            .map_err(|error| OwnershipError::InvalidPackageManifest {
                package: incoming.package.name.clone(),
                reason: error.to_string(),
            })?;

        let previous = self
            .packages
            .iter()
            .find(|record| record.package.name == incoming.package.name);
        let remaining = self
            .packages
            .iter()
            .filter(|record| record.package.name != incoming.package.name)
            .cloned()
            .collect::<Vec<_>>();

        // Validate the installed tree excluding the version being upgraded,
        // then validate the combined ownership graph with the proposed version.
        let existing_index = build_index(&remaining)?;
        let mut combined = remaining.clone();
        combined.push(InstalledPackageRecord::from_manifest(incoming));
        combined.sort_by(|left, right| left.package.name.cmp(&right.package.name));
        let _combined_index = build_index(&combined)?;

        let mut paths_to_claim = Vec::new();
        let mut shared_directories = Vec::new();
        for entry in &incoming.files {
            match existing_index.paths.get(&entry.path) {
                None => paths_to_claim.push(entry.path.clone()),
                Some(existing)
                    if entry.kind == PackageFileKind::Directory
                        && existing.entry.kind == PackageFileKind::Directory
                        && entry.mode == existing.entry.mode =>
                {
                    shared_directories.push(entry.path.clone());
                }
                Some(existing) if entry.kind != existing.entry.kind => {
                    return Err(OwnershipError::PathTypeConflict {
                        path: entry.path.clone(),
                        first_package: existing.owners.iter().next().cloned().unwrap_or_default(),
                        second_package: incoming.package.name.clone(),
                    });
                }
                Some(existing)
                    if entry.kind == PackageFileKind::Directory
                        && existing.entry.kind == PackageFileKind::Directory =>
                {
                    return Err(OwnershipError::DirectoryModeConflict {
                        path: entry.path.clone(),
                        first_mode: existing.entry.mode,
                        second_mode: entry.mode,
                    });
                }
                Some(existing) => {
                    return Err(OwnershipError::FileAlreadyOwned {
                        path: entry.path.clone(),
                        first_package: existing
                            .owners
                            .iter()
                            .next()
                            .cloned()
                            .unwrap_or_default(),
                        second_package: incoming.package.name.clone(),
                    });
                }
            }
        }

        let incoming_paths = incoming
            .files
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<BTreeSet<_>>();
        let paths_to_release = previous
            .into_iter()
            .flat_map(|record| record.files.iter())
            .filter(|entry| !incoming_paths.contains(entry.path.as_str()))
            .map(|entry| entry.path.clone())
            .collect();

        Ok(InstallOwnershipAssessment {
            package_name: incoming.package.name.clone(),
            database_generation: self.generation,
            replacing_existing_version: previous.is_some(),
            paths_to_claim,
            shared_directories,
            paths_to_release,
        })
    }
}

impl FileOwnershipIndex {
    pub fn get(&self, path: &str) -> Option<&OwnedPath> {
        self.paths.get(path)
    }

    pub fn owners(&self, path: &str) -> Option<&BTreeSet<String>> {
        self.paths.get(path).map(|entry| &entry.owners)
    }

    pub fn paths(&self) -> impl Iterator<Item = (&str, &OwnedPath)> {
        self.paths
            .iter()
            .map(|(path, entry)| (path.as_str(), entry))
    }
}

fn build_index(packages: &[InstalledPackageRecord]) -> Result<FileOwnershipIndex, OwnershipError> {
    let mut index = FileOwnershipIndex::default();

    for record in packages {
        for entry in &record.files {
            match index.paths.get_mut(&entry.path) {
                None => {
                    index.paths.insert(
                        entry.path.clone(),
                        OwnedPath {
                            entry: entry.clone(),
                            owners: BTreeSet::from([record.package.name.clone()]),
                        },
                    );
                }
                Some(existing) if existing.entry.kind != entry.kind => {
                    return Err(OwnershipError::PathTypeConflict {
                        path: entry.path.clone(),
                        first_package: existing
                            .owners
                            .iter()
                            .next()
                            .cloned()
                            .unwrap_or_default(),
                        second_package: record.package.name.clone(),
                    });
                }
                Some(existing)
                    if entry.kind == PackageFileKind::Directory
                        && existing.entry.mode == entry.mode =>
                {
                    existing.owners.insert(record.package.name.clone());
                }
                Some(existing)
                    if entry.kind == PackageFileKind::Directory
                        && existing.entry.mode != entry.mode =>
                {
                    return Err(OwnershipError::DirectoryModeConflict {
                        path: entry.path.clone(),
                        first_mode: existing.entry.mode,
                        second_mode: entry.mode,
                    });
                }
                Some(existing) => {
                    return Err(OwnershipError::FileAlreadyOwned {
                        path: entry.path.clone(),
                        first_package: existing
                            .owners
                            .iter()
                            .next()
                            .cloned()
                            .unwrap_or_default(),
                        second_package: record.package.name.clone(),
                    });
                }
            }
        }
    }

    // Detect cross-package file-as-parent conflicts. Each individual archive
    // is validated independently, so this check is needed for the combined tree.
    for path in index.paths.keys() {
        let mut parent = path.as_str();
        while let Some(separator) = parent.rfind('/') {
            parent = &parent[..separator];
            if index
                .paths
                .get(parent)
                .is_some_and(|entry| entry.entry.kind == PackageFileKind::File)
            {
                return Err(OwnershipError::FileParentConflict {
                    file: parent.to_string(),
                    descendant: path.clone(),
                });
            }
        }
    }

    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package_archive::{PackageInputEntry, encode_archive, inspect_archive};
    use std::io::Cursor;

    fn manifest(
        name: &str,
        version: &str,
        entries: Vec<PackageInputEntry>,
    ) -> PackageArchiveManifest {
        let package = PackageInfo {
            name: name.to_string(),
            version: version.to_string(),
            architecture: "x86_64".to_string(),
            abi: "deku1-linux-gnu".to_string(),
            license: "MIT".to_string(),
            dependencies: Vec::new(),
        };
        let archive = encode_archive(package, entries).expect("encode fixture");
        inspect_archive(&mut Cursor::new(archive))
            .expect("inspect fixture")
            .manifest
    }

    fn file(path: &str, content: &[u8]) -> PackageInputEntry {
        PackageInputEntry {
            path: path.to_string(),
            kind: PackageFileKind::File,
            mode: 0o644,
            content: content.to_vec(),
        }
    }

    fn directory(path: &str, mode: u32) -> PackageInputEntry {
        PackageInputEntry {
            path: path.to_string(),
            kind: PackageFileKind::Directory,
            mode,
            content: Vec::new(),
        }
    }

    #[test]
    fn serializes_and_validates_a_canonical_installed_database() {
        let app = manifest(
            "app",
            "1.0-1",
            vec![directory("usr/bin", 0o755), file("usr/bin/app", b"v1")],
        );
        let database = InstalledDatabase::from_manifests(4, [app]).expect("build database");
        let bytes = database.to_json().expect("serialize database");
        let loaded = InstalledDatabase::from_json(&bytes).expect("validate database");
        assert_eq!(loaded, database);
        assert_eq!(loaded.generation, 4);
    }

    #[test]
    fn rejects_multiple_owners_for_a_regular_file() {
        let first = manifest("app-a", "1.0-1", vec![file("usr/bin/shared", b"one")]);
        let second = manifest("app-b", "1.0-1", vec![file("usr/bin/shared", b"two")]);
        assert!(matches!(
            InstalledDatabase::from_manifests(1, [first, second]),
            Err(OwnershipError::FileAlreadyOwned { .. })
        ));
    }

    #[test]
    fn allows_shared_directories_only_when_modes_match() {
        let first = manifest(
            "app-a",
            "1.0-1",
            vec![directory("usr/bin", 0o755), file("usr/bin/a", b"a")],
        );
        let second = manifest(
            "app-b",
            "1.0-1",
            vec![directory("usr/bin", 0o755), file("usr/bin/b", b"b")],
        );
        let database =
            InstalledDatabase::from_manifests(1, [first.clone()]).expect("valid existing database");
        let assessment = database
            .assess_install(&second)
            .expect("shared directory allowed");
        assert_eq!(assessment.shared_directories, vec!["usr/bin"]);
        assert_eq!(assessment.paths_to_claim, vec!["usr/bin/b"]);
        assert!(!assessment.replacing_existing_version);

        let conflicting_mode = manifest(
            "app-b",
            "1.0-1",
            vec![directory("usr/bin", 0o750), file("usr/bin/b", b"b")],
        );
        assert!(matches!(
            database.assess_install(&conflicting_mode),
            Err(OwnershipError::DirectoryModeConflict { .. })
        ));
    }

    #[test]
    fn detects_file_as_parent_conflicts_across_packages() {
        let file_parent = manifest("parent", "1.0-1", vec![file("usr/bin", b"not-a-directory")]);
        let descendant = manifest("child", "1.0-1", vec![file("usr/bin/tool", b"tool")]);
        assert!(matches!(
            InstalledDatabase::from_manifests(1, [file_parent, descendant]),
            Err(OwnershipError::FileParentConflict { .. })
        ));
    }

    #[test]
    fn upgrades_can_replace_own_paths_but_not_another_packages_paths() {
        let old = manifest(
            "app",
            "1.0-1",
            vec![file("usr/bin/app", b"v1"), file("usr/share/old", b"old")],
        );
        let database = InstalledDatabase::from_manifests(8, [old]).expect("existing database");
        let upgraded = manifest("app", "2.0-1", vec![file("usr/bin/app", b"v2")]);
        let assessment = database
            .assess_install(&upgraded)
            .expect("upgrade can replace own path");
        assert!(assessment.replacing_existing_version);
        assert_eq!(assessment.database_generation, 8);
        assert_eq!(assessment.paths_to_claim, vec!["usr/bin/app"]);
        assert_eq!(assessment.paths_to_release, vec!["usr/share/old"]);

        let other = manifest("other", "1.0-1", vec![file("usr/bin/other", b"other")]);
        let database_with_other =
            InstalledDatabase::from_manifests(8, [database.packages[0].as_manifest(), other])
                .expect("database with other package");
        let conflicting = manifest("app", "2.0-1", vec![file("usr/bin/other", b"takeover")]);
        assert!(matches!(
            database_with_other.assess_install(&conflicting),
            Err(OwnershipError::FileAlreadyOwned { .. })
        ));
    }

    #[test]
    fn rejects_unsorted_package_database_and_unknown_json_fields() {
        let app_a = manifest("app-a", "1.0-1", vec![]);
        let app_b = manifest("app-b", "1.0-1", vec![]);
        let unsorted = InstalledDatabase {
            schema_version: 1,
            generation: 0,
            packages: vec![
                InstalledPackageRecord::from_manifest(&app_b),
                InstalledPackageRecord::from_manifest(&app_a),
            ],
        };
        assert!(matches!(
            unsorted.validate(),
            Err(OwnershipError::UnsortedPackages)
        ));

        assert!(matches!(
            InstalledDatabase::from_json(
                br#"{"schema_version":1,"generation":0,"packages":[],"extra":true}"#
            ),
            Err(OwnershipError::InvalidJson(_))
        ));
    }
}
