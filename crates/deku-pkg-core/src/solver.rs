//! Deterministic, version-aware dependency resolution.
//!
//! The resolver is pure: it has no network, filesystem, privilege, or host
//! mutation APIs. It chooses the highest compatible version, backtracks when
//! dependency constraints disagree, and returns a dependency-first plan. The
//! first version deliberately omits virtual provides, conflicts, weak
//! dependencies, package scripts, and repository trust; those are separate
//! contracts and are not implied by a successful resolution.

use crate::version::DekuVersion;
use std::collections::{BTreeMap, BTreeSet};

const MAX_CANDIDATES: usize = 65_536;
const MAX_ROOT_REQUIREMENTS: usize = 512;
const MAX_DEPENDENCIES_PER_CANDIDATE: usize = 256;
const MAX_CONSTRAINTS_PER_REQUIREMENT: usize = 16;
const MAX_CONSTRAINTS_PER_PACKAGE: usize = 1_024;
const MAX_SEARCH_STATES: usize = 100_000;
const MAX_SEARCH_DEPTH: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Equal,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

/// One version predicate, for example >=1.2-1 or <3.0-0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionConstraint {
    pub comparison: Comparison,
    pub version: DekuVersion,
}

impl VersionConstraint {
    /// Parse exactly one comparison token. Whitespace is rejected to keep
    /// recipe syntax unambiguous; callers may trim user-facing input first.
    pub fn parse(value: &str) -> Result<Self, SolveError> {
        let (comparison, raw_version) = if let Some(rest) = value.strip_prefix(">=") {
            (Comparison::GreaterOrEqual, rest)
        } else if let Some(rest) = value.strip_prefix("<=") {
            (Comparison::LessOrEqual, rest)
        } else if let Some(rest) = value.strip_prefix('>') {
            (Comparison::Greater, rest)
        } else if let Some(rest) = value.strip_prefix('<') {
            (Comparison::Less, rest)
        } else if let Some(rest) = value.strip_prefix('=') {
            (Comparison::Equal, rest)
        } else {
            return Err(SolveError::InvalidConstraint(value.to_string()));
        };

        if raw_version.is_empty() || raw_version.trim() != raw_version {
            return Err(SolveError::InvalidConstraint(value.to_string()));
        }
        let version = DekuVersion::parse(raw_version)
            .map_err(|_| SolveError::InvalidConstraint(value.to_string()))?;
        Ok(Self {
            comparison,
            version,
        })
    }

    pub fn matches(&self, candidate: &DekuVersion) -> bool {
        match self.comparison {
            Comparison::Equal => candidate == &self.version,
            Comparison::Greater => candidate > &self.version,
            Comparison::GreaterOrEqual => candidate >= &self.version,
            Comparison::Less => candidate < &self.version,
            Comparison::LessOrEqual => candidate <= &self.version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyRequirement {
    pub name: String,
    /// All predicates are conjunctive. An empty list accepts any version.
    pub constraints: Vec<VersionConstraint>,
}

impl DependencyRequirement {
    pub fn any(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            constraints: Vec::new(),
        }
    }

    pub fn constrained(
        name: impl Into<String>,
        constraints: Vec<VersionConstraint>,
    ) -> Self {
        Self {
            name: name.into(),
            constraints,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageCandidate {
    pub name: String,
    pub version: DekuVersion,
    /// Supported values are x86_64, aarch64, and noarch.
    pub architecture: String,
    pub dependencies: Vec<DependencyRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPackage {
    pub name: String,
    pub version: DekuVersion,
    pub architecture: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionPlan {
    /// Dependency-first order. Ties are deterministic and sorted by package
    /// name; version choices prefer the highest compatible version.
    pub packages: Vec<ResolvedPackage>,
    pub explored_states: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolveError {
    InvalidTargetArchitecture(String),
    InvalidPackageName(String),
    UnsupportedArchitecture(String),
    TooManyCandidates { count: usize, limit: usize },
    TooManyRootRequirements { count: usize, limit: usize },
    TooManyDependencies { package: String, count: usize, limit: usize },
    TooManyConstraints { package: String, count: usize, limit: usize },
    InvalidConstraint(String),
    DuplicateCandidate { name: String, version: String, architecture: String },
    SearchLimitExceeded { limit: usize },
    Unsatisfiable { packages: Vec<String> },
    DependencyCycle(Vec<String>),
}

impl std::fmt::Display for SolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SolveError {}

#[derive(Debug, Clone, Default)]
struct SearchState {
    selected: BTreeMap<String, usize>,
    requirements: BTreeMap<String, Vec<VersionConstraint>>,
}

fn valid_architecture(value: &str) -> bool {
    matches!(value, "x86_64" | "aarch64" | "noarch")
}

fn candidate_satisfies(
    candidate: &PackageCandidate,
    constraints: &[VersionConstraint],
) -> bool {
    constraints
        .iter()
        .all(|constraint| constraint.matches(&candidate.version))
}

fn validate_requirement(
    requirement: &DependencyRequirement,
    owner: &str,
) -> Result<(), SolveError> {
    if !super::valid_name(&requirement.name) {
        return Err(SolveError::InvalidPackageName(requirement.name.clone()));
    }
    if requirement.constraints.len() > MAX_CONSTRAINTS_PER_REQUIREMENT {
        return Err(SolveError::TooManyConstraints {
            package: owner.to_string(),
            count: requirement.constraints.len(),
            limit: MAX_CONSTRAINTS_PER_REQUIREMENT,
        });
    }
    Ok(())
}

fn search(
    state: SearchState,
    catalog: &[PackageCandidate],
    by_name: &BTreeMap<String, Vec<usize>>,
    target_architecture: &str,
    explored_states: &mut usize,
    failures: &mut BTreeSet<String>,
    cycles: &mut Vec<Vec<String>>,
    depth: usize,
) -> Result<Option<SearchState>, SolveError> {
    *explored_states = explored_states
        .checked_add(1)
        .ok_or(SolveError::SearchLimitExceeded {
            limit: MAX_SEARCH_STATES,
        })?;
    if *explored_states > MAX_SEARCH_STATES || depth > MAX_SEARCH_DEPTH {
        return Err(SolveError::SearchLimitExceeded {
            limit: MAX_SEARCH_STATES,
        });
    }

    // A new constraint may invalidate a package that was selected earlier.
    // Returning to the caller lets the earlier choice backtrack to another
    // version instead of accepting an inconsistent plan.
    for (name, index) in &state.selected {
        let requirements = state.requirements.get(name).map(Vec::as_slice).unwrap_or(&[]);
        if !candidate_satisfies(&catalog[*index], requirements) {
            failures.insert(name.clone());
            return Ok(None);
        }
    }

    // Fail-first selection: resolve the name with the fewest compatible
    // candidates; BTreeMap order is the deterministic tie breaker.
    let mut best: Option<(String, Vec<usize>)> = None;
    for (name, requirements) in &state.requirements {
        if state.selected.contains_key(name) {
            continue;
        }

        let choices = by_name
            .get(name)
            .into_iter()
            .flatten()
            .copied()
            .filter(|index| {
                let candidate = &catalog[*index];
                (candidate.architecture == target_architecture
                    || candidate.architecture == "noarch")
                    && candidate_satisfies(candidate, requirements)
            })
            .collect::<Vec<_>>();

        if choices.is_empty() {
            failures.insert(name.clone());
            return Ok(None);
        }

        if best.as_ref().is_none_or(|(_, current)| choices.len() < current.len()) {
            best = Some((name.clone(), choices));
        }
    }

    let Some((name, choices)) = best else {
        // A dependency cycle is not a valid resolution. Record it as a failed
        // branch so an alternate package version can be considered.
        let mut trial_order = Vec::with_capacity(state.selected.len());
        let mut temporary = BTreeSet::new();
        let mut permanent = BTreeSet::new();
        let mut stack = Vec::new();
        for selected_name in state.selected.keys() {
            match build_install_order(
                selected_name,
                &state.selected,
                catalog,
                &mut temporary,
                &mut permanent,
                &mut stack,
                &mut trial_order,
            ) {
                Ok(()) => {}
                Err(SolveError::DependencyCycle(cycle)) => {
                    failures.extend(cycle.iter().cloned());
                    cycles.push(cycle);
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
        }
        return Ok(Some(state));
    };

    for candidate_index in choices {
        let candidate = &catalog[candidate_index];
        let mut next = state.clone();
        next.selected.insert(name.clone(), candidate_index);

        for dependency in &candidate.dependencies {
            let constraints = next
                .requirements
                .entry(dependency.name.clone())
                .or_default();
            if constraints.len() + dependency.constraints.len() > MAX_CONSTRAINTS_PER_PACKAGE {
                return Err(SolveError::TooManyConstraints {
                    package: dependency.name.clone(),
                    count: constraints.len() + dependency.constraints.len(),
                    limit: MAX_CONSTRAINTS_PER_PACKAGE,
                });
            }
            constraints.extend(dependency.constraints.iter().cloned());
        }

        if let Some(solution) = search(
            next,
            catalog,
            by_name,
            target_architecture,
            explored_states,
            failures,
            cycles,
            depth + 1,
        )? {
            return Ok(Some(solution));
        }
    }

    Ok(None)
}

fn build_install_order(
    name: &str,
    selected: &BTreeMap<String, usize>,
    catalog: &[PackageCandidate],
    temporary: &mut BTreeSet<String>,
    permanent: &mut BTreeSet<String>,
    stack: &mut Vec<String>,
    output: &mut Vec<ResolvedPackage>,
) -> Result<(), SolveError> {
    if permanent.contains(name) {
        return Ok(());
    }
    if temporary.contains(name) {
        let start = stack.iter().position(|entry| entry == name).unwrap_or(0);
        let mut cycle = stack[start..].to_vec();
        cycle.push(name.to_string());
        return Err(SolveError::DependencyCycle(cycle));
    }

    let index = selected
        .get(name)
        .copied()
        .ok_or_else(|| SolveError::Unsatisfiable {
            packages: vec![name.to_string()],
        })?;
    temporary.insert(name.to_string());
    stack.push(name.to_string());

    let candidate = &catalog[index];
    let mut dependencies = candidate
        .dependencies
        .iter()
        .map(|dependency| dependency.name.clone())
        .filter(|dependency| selected.contains_key(dependency))
        .collect::<Vec<_>>();
    dependencies.sort();
    dependencies.dedup();

    for dependency in dependencies {
        build_install_order(
            &dependency,
            selected,
            catalog,
            temporary,
            permanent,
            stack,
            output,
        )?;
    }

    stack.pop();
    temporary.remove(name);
    permanent.insert(name.to_string());
    output.push(ResolvedPackage {
        name: candidate.name.clone(),
        version: candidate.version.clone(),
        architecture: candidate.architecture.clone(),
    });
    Ok(())
}

/// Resolve package requirements against a candidate catalog.
///
/// The resolver backtracks across versions when shared dependencies impose
/// conflicting constraints. Its output is deterministic for the same inputs.
/// This first milestone intentionally supports named dependencies and version
/// comparisons only; it does not implement provides/conflicts or weak deps.
pub fn resolve(
    catalog: &[PackageCandidate],
    roots: &[DependencyRequirement],
    target_architecture: &str,
) -> Result<ResolutionPlan, SolveError> {
    if !matches!(target_architecture, "x86_64" | "aarch64") {
        return Err(SolveError::InvalidTargetArchitecture(
            target_architecture.to_string(),
        ));
    }
    if catalog.len() > MAX_CANDIDATES {
        return Err(SolveError::TooManyCandidates {
            count: catalog.len(),
            limit: MAX_CANDIDATES,
        });
    }
    if roots.len() > MAX_ROOT_REQUIREMENTS {
        return Err(SolveError::TooManyRootRequirements {
            count: roots.len(),
            limit: MAX_ROOT_REQUIREMENTS,
        });
    }

    let mut by_name = BTreeMap::<String, Vec<usize>>::new();
    let mut identities = BTreeSet::<(String, DekuVersion, String)>::new();

    for (index, candidate) in catalog.iter().enumerate() {
        if !super::valid_name(&candidate.name) {
            return Err(SolveError::InvalidPackageName(candidate.name.clone()));
        }
        if !valid_architecture(&candidate.architecture) {
            return Err(SolveError::UnsupportedArchitecture(
                candidate.architecture.clone(),
            ));
        }
        if candidate.dependencies.len() > MAX_DEPENDENCIES_PER_CANDIDATE {
            return Err(SolveError::TooManyDependencies {
                package: candidate.name.clone(),
                count: candidate.dependencies.len(),
                limit: MAX_DEPENDENCIES_PER_CANDIDATE,
            });
        }
        for dependency in &candidate.dependencies {
            validate_requirement(dependency, &candidate.name)?;
        }
        let identity = (
            candidate.name.clone(),
            candidate.version.clone(),
            candidate.architecture.clone(),
        );
        if !identities.insert(identity) {
            return Err(SolveError::DuplicateCandidate {
                name: candidate.name.clone(),
                version: candidate.version.canonical(),
                architecture: candidate.architecture.clone(),
            });
        }
        by_name.entry(candidate.name.clone()).or_default().push(index);
    }

    for choices in by_name.values_mut() {
        choices.sort_by(|left, right| {
            let left_candidate = &catalog[*left];
            let right_candidate = &catalog[*right];
            right_candidate
                .version
                .cmp(&left_candidate.version)
                .then_with(|| {
                    let left_arch = usize::from(left_candidate.architecture != target_architecture);
                    let right_arch =
                        usize::from(right_candidate.architecture != target_architecture);
                    left_arch.cmp(&right_arch)
                })
                .then_with(|| left_candidate.architecture.cmp(&right_candidate.architecture))
        });
    }

    let mut state = SearchState::default();
    for requirement in roots {
        validate_requirement(requirement, "requested root")?;
        let constraints = state
            .requirements
            .entry(requirement.name.clone())
            .or_default();
        if constraints.len() + requirement.constraints.len() > MAX_CONSTRAINTS_PER_PACKAGE {
            return Err(SolveError::TooManyConstraints {
                package: requirement.name.clone(),
                count: constraints.len() + requirement.constraints.len(),
                limit: MAX_CONSTRAINTS_PER_PACKAGE,
            });
        }
        constraints.extend(requirement.constraints.iter().cloned());
    }

    let mut explored_states = 0;
    let mut failures = BTreeSet::new();
    let mut cycles = Vec::new();
    let solution = match search(
        state,
        catalog,
        &by_name,
        target_architecture,
        &mut explored_states,
        &mut failures,
        &mut cycles,
        0,
    )? {
        Some(solution) => solution,
        None => {
            if let Some(cycle) = cycles.into_iter().next() {
                return Err(SolveError::DependencyCycle(cycle));
            }
            if failures.is_empty() {
                failures.extend(roots.iter().map(|requirement| requirement.name.clone()));
            }
            return Err(SolveError::Unsatisfiable {
                packages: failures.into_iter().collect(),
            });
        }
    };

    let mut output = Vec::with_capacity(solution.selected.len());
    let mut temporary = BTreeSet::new();
    let mut permanent = BTreeSet::new();
    let mut stack = Vec::new();
    for name in solution.selected.keys() {
        build_install_order(
            name,
            &solution.selected,
            catalog,
            &mut temporary,
            &mut permanent,
            &mut stack,
            &mut output,
        )?;
    }

    Ok(ResolutionPlan {
        packages: output,
        explored_states,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn constraint(expression: &str) -> VersionConstraint {
        VersionConstraint::parse(expression).expect("valid constraint")
    }

    fn requirement(name: &str, constraints: &[&str]) -> DependencyRequirement {
        DependencyRequirement::constrained(
            name,
            constraints.iter().map(|item| constraint(item)).collect(),
        )
    }

    fn candidate(
        name: &str,
        version: &str,
        architecture: &str,
        dependencies: Vec<DependencyRequirement>,
    ) -> PackageCandidate {
        PackageCandidate {
            name: name.to_string(),
            version: DekuVersion::parse(version).expect("valid package version"),
            architecture: architecture.to_string(),
            dependencies,
        }
    }

    #[test]
    fn selects_highest_version_satisfying_all_constraints() {
        let catalog = vec![
            candidate("libc", "1.9-1", "x86_64", vec![]),
            candidate("libc", "2.4-1", "x86_64", vec![]),
            candidate("libc", "2.9-1", "x86_64", vec![]),
            candidate("libc", "3.0-1", "x86_64", vec![]),
        ];
        let plan = resolve(
            &catalog,
            &[requirement("libc", &[">=2.0-0", "<3.0-0"])],
            "x86_64",
        )
        .expect("version range resolves");
        assert_eq!(plan.packages.len(), 1);
        assert_eq!(plan.packages[0].version.canonical(), "2.9-1");
    }

    #[test]
    fn backtracks_when_a_later_constraint_invalidates_the_newest_version() {
        let catalog = vec![
            candidate(
                "app",
                "2.0-1",
                "x86_64",
                vec![requirement("libc", &[">=2.0-0"])],
            ),
            candidate(
                "app",
                "1.0-1",
                "x86_64",
                vec![requirement("libc", &["<2.0-0"])],
            ),
            candidate("libc", "1.9-1", "x86_64", vec![]),
            candidate("libc", "2.1-1", "x86_64", vec![]),
        ];
        let plan = resolve(
            &catalog,
            &[
                DependencyRequirement::any("app"),
                requirement("libc", &["<2.0-0"]),
            ],
            "x86_64",
        )
        .expect("solver must backtrack to app 1");
        let app = plan.packages.iter().find(|package| package.name == "app").unwrap();
        let libc = plan.packages.iter().find(|package| package.name == "libc").unwrap();
        assert_eq!(app.version.canonical(), "1.0-1");
        assert_eq!(libc.version.canonical(), "1.9-1");
        assert!(plan.packages.iter().position(|package| package.name == "libc")
            < plan.packages.iter().position(|package| package.name == "app"));
    }

    #[test]
    fn prefers_native_architecture_over_noarch_at_the_same_version() {
        let catalog = vec![
            candidate("tool", "1.0-1", "noarch", vec![]),
            candidate("tool", "1.0-1", "x86_64", vec![]),
            candidate("tool", "1.0-1", "aarch64", vec![]),
        ];
        let plan = resolve(
            &catalog,
            &[DependencyRequirement::any("tool")],
            "x86_64",
        )
        .expect("architecture-aware resolution");
        assert_eq!(plan.packages[0].architecture, "x86_64");

        let arm_plan = resolve(
            &catalog,
            &[DependencyRequirement::any("tool")],
            "aarch64",
        )
        .expect("arm architecture-aware resolution");
        assert_eq!(arm_plan.packages[0].architecture, "aarch64");
    }

    #[test]
    fn returns_dependency_first_order_and_is_independent_of_catalog_order() {
        let items = vec![
            candidate("app", "1.0-1", "x86_64", vec![DependencyRequirement::any("lib")]),
            candidate("lib", "1.0-1", "x86_64", vec![DependencyRequirement::any("base")]),
            candidate("base", "1.0-1", "noarch", vec![]),
        ];
        let first = resolve(&items, &[DependencyRequirement::any("app")], "x86_64").unwrap();
        let mut reversed = items.clone();
        reversed.reverse();
        let second = resolve(&reversed, &[DependencyRequirement::any("app")], "x86_64").unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first.packages.iter().map(|package| package.name.as_str()).collect::<Vec<_>>(),
            vec!["base", "lib", "app"]
        );
    }

    #[test]
    fn rejects_missing_packages_and_unsupported_target_architecture() {
        assert!(matches!(
            resolve(&[], &[DependencyRequirement::any("missing")], "x86_64"),
            Err(SolveError::Unsatisfiable { .. })
        ));
        assert!(matches!(
            resolve(&[], &[], "i686"),
            Err(SolveError::InvalidTargetArchitecture(_))
        ));
    }

    #[test]
    fn rejects_duplicate_candidates_with_the_same_identity() {
        let item = candidate("lib", "1.0-1", "x86_64", vec![]);
        assert!(matches!(
            resolve(&[item.clone(), item], &[DependencyRequirement::any("lib")], "x86_64"),
            Err(SolveError::DuplicateCandidate { .. })
        ));
    }

    #[test]
    fn detects_dependency_cycles_instead_of_returning_an_install_order() {
        let catalog = vec![
            candidate("a", "1.0-1", "x86_64", vec![DependencyRequirement::any("b")]),
            candidate("b", "1.0-1", "x86_64", vec![DependencyRequirement::any("a")]),
        ];
        assert!(matches!(
            resolve(&catalog, &[DependencyRequirement::any("a")], "x86_64"),
            Err(SolveError::DependencyCycle(_))
        ));
    }

    #[test]
    fn parses_explicit_constraint_operators_and_rejects_ambiguous_tokens() {
        assert!(VersionConstraint::parse(">=1.0-1").is_ok());
        assert!(VersionConstraint::parse("=1.0-1").is_ok());
        for invalid in ["", "1.0", "==1.0", ">= 1.0", "<=", ">2.0 "] {
            assert!(
                VersionConstraint::parse(invalid).is_err(),
                "unexpectedly accepted {invalid}"
            );
        }
    }

    #[test]
    fn no_solution_reports_constraint_conflicts() {
        let catalog = vec![
            candidate(
                "app",
                "1.0-1",
                "x86_64",
                vec![requirement("lib", &[">=2.0-0"])],
            ),
            candidate("lib", "1.0-1", "x86_64", vec![]),
        ];
        assert!(matches!(
            resolve(
                &catalog,
                &[DependencyRequirement::any("app")],
                "x86_64"
            ),
            Err(SolveError::Unsatisfiable { .. })
        ));
    }
}
