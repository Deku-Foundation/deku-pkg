//! Validated JSON catalog for the native version-aware resolver.
//!
//! This is distinct from the legacy schema-v1 catalog in lib.rs, which models
//! a single package per name. SolverCatalog accepts multiple versions of the
//! same package and keeps each selected artifact pinned to its file name and
//! SHA-256. It is still metadata, not publisher authentication: callers must
//! verify repository trust before treating it as an authoritative catalog.

use crate::Artifact;
use crate::solver::{
    DependencyRequirement, PackageCandidate, ResolutionPlan, ResolvedPackage, SolveError,
    VersionConstraint, resolve,
};
use crate::version::DekuVersion;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_SOLVER_CATALOG_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOLVER_CATALOG_PACKAGES: usize = 65_536;
const MAX_SOLVER_CATALOG_DEPENDENCIES: usize = 256;
const MAX_SOLVER_CATALOG_CONSTRAINTS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SolverCatalog {
    pub schema_version: u32,
    pub packages: Vec<SolverCatalogPackage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SolverCatalogPackage {
    pub name: String,
    /// Must use Deku's canonical epoch/upstream-release rendering.
    pub version: String,
    pub architecture: String,
    pub artifact: Artifact,
    #[serde(default)]
    pub dependencies: Vec<SolverCatalogDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SolverCatalogDependency {
    pub name: String,
    /// Conjunctive constraints such as [">=1.2-1", "<2.0-0"].
    #[serde(default)]
    pub constraints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedArtifact {
    pub name: String,
    pub version: DekuVersion,
    pub architecture: String,
    pub artifact: Artifact,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedResolutionPlan {
    /// Exact artifact references in dependency-first order.
    pub packages: Vec<PlannedArtifact>,
    pub explored_states: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolverCatalogError {
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
    InvalidPackageName(String),
    InvalidVersion(String),
    NonCanonicalVersion(String),
    UnsupportedArchitecture(String),
    InvalidArtifactFile(String),
    InvalidDigest(String),
    TooManyDependencies {
        package: String,
        count: usize,
        limit: usize,
    },
    DuplicateDependency {
        package: String,
        dependency: String,
    },
    SelfDependency(String),
    TooManyConstraints {
        package: String,
        dependency: String,
        count: usize,
        limit: usize,
    },
    DuplicatePackage {
        name: String,
        version: String,
        architecture: String,
    },
    Resolution(SolveError),
}

impl std::fmt::Display for SolverCatalogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SolverCatalogError {}

impl From<SolveError> for SolverCatalogError {
    fn from(value: SolveError) -> Self {
        Self::Resolution(value)
    }
}

impl SolverCatalog {
    /// Bound input size before JSON deserialization allocates the catalog.
    pub fn from_json(bytes: &[u8]) -> Result<Self, SolverCatalogError> {
        if bytes.len() > MAX_SOLVER_CATALOG_JSON_BYTES {
            return Err(SolverCatalogError::MetadataTooLarge {
                size: bytes.len(),
                limit: MAX_SOLVER_CATALOG_JSON_BYTES,
            });
        }
        let catalog: Self = serde_json::from_slice(bytes)
            .map_err(|error| SolverCatalogError::InvalidJson(error.to_string()))?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<(), SolverCatalogError> {
        if self.schema_version != 1 {
            return Err(SolverCatalogError::UnsupportedSchema);
        }
        if self.packages.len() > MAX_SOLVER_CATALOG_PACKAGES {
            return Err(SolverCatalogError::TooManyPackages {
                count: self.packages.len(),
                limit: MAX_SOLVER_CATALOG_PACKAGES,
            });
        }

        let mut identities = BTreeSet::<(String, DekuVersion, String)>::new();
        for package in &self.packages {
            if !super::valid_name(&package.name) {
                return Err(SolverCatalogError::InvalidPackageName(package.name.clone()));
            }
            let version = DekuVersion::parse(&package.version)
                .map_err(|_| SolverCatalogError::InvalidVersion(package.name.clone()))?;
            if version.canonical() != package.version {
                return Err(SolverCatalogError::NonCanonicalVersion(
                    package.name.clone(),
                ));
            }
            if !matches!(
                package.architecture.as_str(),
                "x86_64" | "aarch64" | "noarch"
            ) {
                return Err(SolverCatalogError::UnsupportedArchitecture(
                    package.architecture.clone(),
                ));
            }
            if !super::valid_file(&package.artifact.file) {
                return Err(SolverCatalogError::InvalidArtifactFile(
                    package.artifact.file.clone(),
                ));
            }
            if !super::valid_digest(&package.artifact.sha256) {
                return Err(SolverCatalogError::InvalidDigest(package.name.clone()));
            }
            if package.dependencies.len() > MAX_SOLVER_CATALOG_DEPENDENCIES {
                return Err(SolverCatalogError::TooManyDependencies {
                    package: package.name.clone(),
                    count: package.dependencies.len(),
                    limit: MAX_SOLVER_CATALOG_DEPENDENCIES,
                });
            }

            if !identities.insert((package.name.clone(), version, package.architecture.clone())) {
                return Err(SolverCatalogError::DuplicatePackage {
                    name: package.name.clone(),
                    version: package.version.clone(),
                    architecture: package.architecture.clone(),
                });
            }

            let mut dependency_names = BTreeSet::new();
            for dependency in &package.dependencies {
                if !super::valid_name(&dependency.name) {
                    return Err(SolverCatalogError::InvalidPackageName(
                        dependency.name.clone(),
                    ));
                }
                if !dependency_names.insert(dependency.name.as_str()) {
                    return Err(SolverCatalogError::DuplicateDependency {
                        package: package.name.clone(),
                        dependency: dependency.name.clone(),
                    });
                }
                if dependency.name == package.name {
                    return Err(SolverCatalogError::SelfDependency(package.name.clone()));
                }
                if dependency.constraints.len() > MAX_SOLVER_CATALOG_CONSTRAINTS {
                    return Err(SolverCatalogError::TooManyConstraints {
                        package: package.name.clone(),
                        dependency: dependency.name.clone(),
                        count: dependency.constraints.len(),
                        limit: MAX_SOLVER_CATALOG_CONSTRAINTS,
                    });
                }
                for constraint in &dependency.constraints {
                    VersionConstraint::parse(constraint).map_err(|_| {
                        SolverCatalogError::Resolution(SolveError::InvalidConstraint(
                            constraint.clone(),
                        ))
                    })?;
                }
            }
        }
        Ok(())
    }

    fn candidates(&self) -> Result<Vec<PackageCandidate>, SolverCatalogError> {
        self.packages
            .iter()
            .map(|package| {
                let version = DekuVersion::parse(&package.version)
                    .map_err(|_| SolverCatalogError::InvalidVersion(package.name.clone()))?;
                let dependencies = package
                    .dependencies
                    .iter()
                    .map(|dependency| {
                        let constraints = dependency
                            .constraints
                            .iter()
                            .map(|constraint| VersionConstraint::parse(constraint))
                            .collect::<Result<Vec<_>, _>>()?;
                        Ok(DependencyRequirement::constrained(
                            dependency.name.clone(),
                            constraints,
                        ))
                    })
                    .collect::<Result<Vec<_>, SolveError>>()?;
                Ok(PackageCandidate {
                    name: package.name.clone(),
                    version,
                    architecture: package.architecture.clone(),
                    dependencies,
                })
            })
            .collect()
    }

    /// Resolve requested package requirements and pin each selected candidate
    /// to its exact artifact name and SHA-256 from this validated catalog.
    pub fn plan(
        &self,
        roots: &[DependencyRequirement],
        target_architecture: &str,
    ) -> Result<PinnedResolutionPlan, SolverCatalogError> {
        self.validate()?;
        let candidates = self.candidates()?;
        let resolution: ResolutionPlan = resolve(&candidates, roots, target_architecture)?;

        let mut by_identity =
            BTreeMap::<(String, DekuVersion, String), &SolverCatalogPackage>::new();
        for package in &self.packages {
            let version = DekuVersion::parse(&package.version)
                .map_err(|_| SolverCatalogError::InvalidVersion(package.name.clone()))?;
            by_identity.insert(
                (package.name.clone(), version, package.architecture.clone()),
                package,
            );
        }

        let mut packages = Vec::with_capacity(resolution.packages.len());
        for resolved in resolution.packages {
            packages.push(pin_artifact(&by_identity, resolved)?);
        }

        Ok(PinnedResolutionPlan {
            packages,
            explored_states: resolution.explored_states,
        })
    }
}

fn pin_artifact(
    by_identity: &BTreeMap<(String, DekuVersion, String), &SolverCatalogPackage>,
    resolved: ResolvedPackage,
) -> Result<PlannedArtifact, SolverCatalogError> {
    let key = (
        resolved.name.clone(),
        resolved.version.clone(),
        resolved.architecture.clone(),
    );
    let package = by_identity.get(&key).ok_or_else(|| {
        SolverCatalogError::Resolution(SolveError::Unsatisfiable {
            packages: vec![resolved.name.clone()],
        })
    })?;
    Ok(PlannedArtifact {
        name: resolved.name,
        version: resolved.version,
        architecture: resolved.architecture,
        artifact: package.artifact.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(file: &str, byte: char) -> Artifact {
        Artifact {
            file: file.to_string(),
            sha256: byte.to_string().repeat(64),
        }
    }

    fn package(
        name: &str,
        version: &str,
        architecture: &str,
        file: &str,
        digest_char: char,
        dependencies: Vec<SolverCatalogDependency>,
    ) -> SolverCatalogPackage {
        SolverCatalogPackage {
            name: name.to_string(),
            version: version.to_string(),
            architecture: architecture.to_string(),
            artifact: artifact(file, digest_char),
            dependencies,
        }
    }

    fn dependency(name: &str, constraints: &[&str]) -> SolverCatalogDependency {
        SolverCatalogDependency {
            name: name.to_string(),
            constraints: constraints.iter().map(|item| item.to_string()).collect(),
        }
    }

    #[test]
    fn parses_json_and_pins_the_exact_artifact_selected_by_the_solver() {
        let catalog = SolverCatalog {
            schema_version: 1,
            packages: vec![
                package(
                    "app",
                    "1.0-1",
                    "x86_64",
                    "app-1.0-1-x86_64.dpak",
                    'a',
                    vec![dependency("lib", &[">=2.0-0", "<3.0-0"])],
                ),
                package("lib", "2.0-1", "x86_64", "lib-2.0-1.pkg", 'b', vec![]),
                package("lib", "2.9-1", "x86_64", "lib-2.9-1.pkg", 'c', vec![]),
                package("lib", "3.0-1", "x86_64", "lib-3.0-1.pkg", 'd', vec![]),
            ],
        };
        let json = serde_json::to_vec(&catalog).expect("serialize fixture");
        let parsed = SolverCatalog::from_json(&json).expect("parse validated catalog");
        let plan = parsed
            .plan(&[DependencyRequirement::any("app")], "x86_64")
            .expect("create pinned plan");

        assert_eq!(
            plan.packages
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            vec!["lib", "app"]
        );
        assert_eq!(plan.packages[0].version.canonical(), "2.9-1");
        assert_eq!(plan.packages[0].artifact.file, "lib-2.9-1.pkg");
        assert_eq!(plan.packages[0].artifact.sha256, "c".repeat(64));
    }

    #[test]
    fn documented_example_is_valid_and_produces_a_pinned_plan() {
        let catalog =
            SolverCatalog::from_json(include_bytes!("../../../examples/solver-catalog-v1.json"))
                .expect("example catalog is valid");
        let plan = catalog
            .plan(&[DependencyRequirement::any("desktop-shell")], "x86_64")
            .expect("example plan resolves");
        assert_eq!(plan.packages.len(), 2);
        assert_eq!(plan.packages[0].name, "libc");
        assert_eq!(plan.packages[1].name, "desktop-shell");
    }

    #[test]
    fn rejects_noncanonical_versions_and_invalid_artifact_digests() {
        let mut catalog = SolverCatalog {
            schema_version: 1,
            packages: vec![package("lib", "1.01-1", "x86_64", "lib.pkg", 'a', vec![])],
        };
        assert!(matches!(
            catalog.validate(),
            Err(SolverCatalogError::NonCanonicalVersion(_))
        ));

        catalog.packages[0].version = "1.1-1".to_string();
        catalog.packages[0].artifact.sha256 = "not-a-digest".to_string();
        assert!(matches!(
            catalog.validate(),
            Err(SolverCatalogError::InvalidDigest(_))
        ));
    }

    #[test]
    fn rejects_duplicate_package_identity_and_duplicate_dependencies() {
        let same = package("lib", "1.0-1", "x86_64", "lib.pkg", 'a', vec![]);
        let duplicate_catalog = SolverCatalog {
            schema_version: 1,
            packages: vec![same.clone(), same],
        };
        assert!(matches!(
            duplicate_catalog.validate(),
            Err(SolverCatalogError::DuplicatePackage { .. })
        ));

        let dependency_catalog = SolverCatalog {
            schema_version: 1,
            packages: vec![package(
                "app",
                "1.0-1",
                "x86_64",
                "app.pkg",
                'a',
                vec![
                    dependency("lib", &[">=1.0-0"]),
                    dependency("lib", &["<2.0-0"]),
                ],
            )],
        };
        assert!(matches!(
            dependency_catalog.validate(),
            Err(SolverCatalogError::DuplicateDependency { .. })
        ));
    }

    #[test]
    fn rejects_self_dependencies_before_resolution() {
        let catalog = SolverCatalog {
            schema_version: 1,
            packages: vec![package(
                "app",
                "1.0-1",
                "x86_64",
                "app.pkg",
                'a',
                vec![dependency("app", &[])],
            )],
        };
        assert!(matches!(
            catalog.validate(),
            Err(SolverCatalogError::SelfDependency(_))
        ));
    }

    #[test]
    fn bounds_json_size_before_deserialization() {
        let oversized = vec![b' '; MAX_SOLVER_CATALOG_JSON_BYTES + 1];
        assert!(matches!(
            SolverCatalog::from_json(&oversized),
            Err(SolverCatalogError::MetadataTooLarge { .. })
        ));
    }
}
