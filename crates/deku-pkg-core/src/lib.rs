//! Experimental, side-effect-free core for Deku package metadata.
//! This crate validates a small catalog and computes a deterministic dependency order.
//! It does not download, install, execute package scripts, or mutate the host.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase().then_some(true).unwrap_or(false)
            || (!value.is_empty()
                && value.len() <= 128
                && value.as_bytes()[0].is_ascii_digit()
                && value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._+-".contains(&b)))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_file(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 180
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
        && value != "."
        && value != ".."
}

impl Catalog {
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.schema_version != 1 {
            return Err(CatalogError::UnsupportedSchema);
        }
        let mut by_name = BTreeMap::new();
        for package in &self.packages {
            if !valid_name(&package.name) {
                return Err(CatalogError::InvalidPackageName(package.name.clone()));
            }
            if package.version.is_empty() || package.version.len() > 128 || package.version.trim() != package.version {
                return Err(CatalogError::InvalidVersion(package.name.clone()));
            }
            if !matches!(package.architecture.as_str(), "x86_64" | "aarch64" | "noarch") {
                return Err(CatalogError::UnsupportedArchitecture(package.architecture.clone()));
            }
            if !valid_file(&package.artifact.file) {
                return Err(CatalogError::InvalidArtifactFile(package.artifact.file.clone()));
            }
            if !valid_digest(&package.artifact.sha256) {
                return Err(CatalogError::InvalidDigest(package.name.clone()));
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
        let mut packages = BTreeMap::<&str, &Package>::new();
        for package in &self.packages {
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
            visit(name, &packages, &mut temporary, &mut permanent, &mut stack, &mut result)?;
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
        let catalog = Catalog { schema_version: 1, packages: vec![pkg("app", &["lib"]), pkg("lib", &[])] };
        assert_eq!(catalog.validate(), Ok(()));
        assert_eq!(catalog.install_order().unwrap(), vec!["lib", "app"]);
    }

    #[test]
    fn unknown_json_fields_are_rejected() {
        let json = r#"{"schema_version":1,"packages":[],"run":"arbitrary shell"}"#;
        assert!(serde_json::from_str::<Catalog>(json).is_err());
    }

    #[test]
    fn duplicate_packages_are_rejected() {
        let catalog = Catalog { schema_version: 1, packages: vec![pkg("lib", &[]), pkg("lib", &[])] };
        assert!(matches!(catalog.validate(), Err(CatalogError::DuplicatePackage(_))));
    }

    #[test]
    fn missing_dependency_is_rejected() {
        let catalog = Catalog { schema_version: 1, packages: vec![pkg("app", &["missing"])] };
        assert!(matches!(catalog.validate(), Err(CatalogError::MissingDependency { .. })));
    }

    #[test]
    fn dependency_cycle_is_rejected() {
        let catalog = Catalog { schema_version: 1, packages: vec![pkg("app", &["lib"]), pkg("lib", &["app"])] };
        assert!(matches!(catalog.validate(), Err(CatalogError::DependencyCycle(_))));
    }

    #[test]
    fn malformed_digest_is_rejected() {
        let mut package = pkg("app", &[]);
        package.artifact.sha256 = "not-a-digest".into();
        let catalog = Catalog { schema_version: 1, packages: vec![package] };
        assert!(matches!(catalog.validate(), Err(CatalogError::InvalidDigest(_))));
    }

    #[test]
    fn path_traversal_filename_is_rejected() {
        let mut package = pkg("app", &[]);
        package.artifact.file = "../payload".into();
        let catalog = Catalog { schema_version: 1, packages: vec![package] };
        assert!(matches!(catalog.validate(), Err(CatalogError::InvalidArtifactFile(_))));
    }
}
