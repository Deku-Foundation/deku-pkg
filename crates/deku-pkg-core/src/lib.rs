//! Experimental, side-effect-free core for Deku package metadata.
//! This crate validates a bounded catalog and computes a deterministic dependency order.
//! It does not download, install, execute package scripts, or mutate the host.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_CATALOG_PACKAGES: usize = 4_096;
const MAX_PACKAGE_DEPENDENCIES: usize = 256;
const MAX_DEPENDENCY_DEPTH: usize = 512;
const MAX_PACKAGE_NAME_LEN: usize = 128;
const MAX_VERSION_LEN: usize = 128;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogError {
    UnsupportedSchema,
    TooManyPackages { count: usize, limit: usize },
    TooManyDependencies { package: String, count: usize, limit: usize },
    DependencyDepthExceeded { limit: usize },
    InvalidPackageName(String),
    InvalidVersion(String),
    UnsupportedArchitecture(String),
    InvalidArtifactFile(String),
    InvalidDigest(String),
    DuplicatePackage(String),
    DuplicateDependency { package: String, dependency: String },
    SelfDependency(String),
    MissingDependency { package: String, dependency: String },
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
    !value.is_empty()
        && value.len() <= MAX_VERSION_LEN
        && value.trim() == value
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+:-~".contains(&b))
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
    /// Validate metadata before trusting it as input to a planner.
    ///
    /// These bounds limit graph complexity, but the caller must also limit the
    /// raw JSON byte length before deserializing an untrusted catalog.
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

            let package = packages.get(name).ok_or_else(|| CatalogError::MissingDependency {
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
        for name in ["Uppercase", "1starts-with-digit", "name with spaces", "../escape"] {
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
}
