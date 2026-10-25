use deku_pkg_core::package_archive::{PackageFileKind, inspect_archive};
use deku_pkg_core::solver::{DependencyRequirement, VersionConstraint};
use deku_pkg_core::solver_catalog::SolverCatalog;
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::process::ExitCode;

fn print_usage() {
    println!(
        "Usage:\n  deku-pkg inspect <archive>\n  deku-pkg verify <archive>\n  deku-pkg files <archive>\n  deku-pkg plan <catalog.json> <x86_64|aarch64> <package[>=version,...]>...\n  deku-pkg --version"
    );
}

fn print_summary(
    archive_size: u64,
    payload_size: u64,
    manifest: &deku_pkg_core::package_archive::PackageArchiveManifest,
) {
    println!("Package: {}", manifest.package.name);
    println!("Version: {}", manifest.package.version);
    println!("Architecture: {}", manifest.package.architecture);
    println!("Deku ABI: {}", manifest.package.abi);
    println!("License expression: {}", manifest.package.license);
    if manifest.package.dependencies.is_empty() {
        println!("Runtime dependencies: (none)");
    } else {
        println!(
            "Runtime dependencies: {}",
            manifest.package.dependencies.join(", ")
        );
    }
    println!("Manifest entries: {}", manifest.files.len());
    println!("Payload bytes: {payload_size}");
    println!("Archive bytes: {archive_size}");
    println!("Archive integrity: verified (per-file SHA-256)");
    println!("Publisher authentication: not provided by the archive format");
}

fn parse_root_requirement(value: &str) -> Result<DependencyRequirement, String> {
    if value.is_empty() || value.trim() != value {
        return Err(
            "requirement must be non-empty and contain no surrounding whitespace".to_string(),
        );
    }

    let operator_index = value
        .char_indices()
        .find(|(_, character)| matches!(*character, '<' | '>' | '='))
        .map(|(index, _)| index);

    let Some(index) = operator_index else {
        return Ok(DependencyRequirement::any(value));
    };
    let name = &value[..index];
    let raw_constraints = &value[index..];
    if name.is_empty() {
        return Err("requirement is missing a package name".to_string());
    }
    if name.trim() != name {
        return Err("package name cannot contain surrounding whitespace".to_string());
    }

    let constraints = raw_constraints
        .split(',')
        .map(|token| {
            VersionConstraint::parse(token)
                .map_err(|_| format!("invalid version constraint: {token}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DependencyRequirement::constrained(name, constraints))
}

fn run_plan(args: &[OsString]) -> ExitCode {
    if args.len() < 4 {
        print_usage();
        eprintln!(
            "deku-pkg: plan requires a catalog, target architecture, and at least one package"
        );
        return ExitCode::from(2);
    }

    let Some(architecture) = args[2].to_str() else {
        eprintln!("deku-pkg: target architecture must be valid UTF-8");
        return ExitCode::from(2);
    };
    let roots = match args[3..]
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .ok_or_else(|| "package requirement must be valid UTF-8".to_string())
                .and_then(parse_root_requirement)
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(roots) => roots,
        Err(error) => {
            eprintln!("deku-pkg: invalid package requirement: {error}");
            return ExitCode::from(2);
        }
    };

    let path = PathBuf::from(&args[1]);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("deku-pkg: cannot open {}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    };

    // Read at most the catalog limit plus one byte so a hostile file cannot
    // cause an unbounded allocation before the JSON parser enforces limits.
    let max_read = 16 * 1024 * 1024 + 1;
    let mut bytes = Vec::new();
    if let Err(error) = BufReader::new(file).take(max_read).read_to_end(&mut bytes) {
        eprintln!("deku-pkg: cannot read {}: {error}", path.display());
        return ExitCode::FAILURE;
    }

    let catalog = match SolverCatalog::from_json(&bytes) {
        Ok(catalog) => catalog,
        Err(error) => {
            eprintln!(
                "deku-pkg: invalid solver catalog {}: {error}",
                path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let plan = match catalog.plan(&roots, architecture) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("deku-pkg: dependency resolution failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("Target architecture: {architecture}");
    println!("Packages in plan: {}", plan.packages.len());
    println!("Resolver states explored: {}", plan.explored_states);
    for package in &plan.packages {
        println!(
            "{} {} {} {} sha256:{}",
            package.name,
            package.version,
            package.architecture,
            package.artifact.file,
            package.artifact.sha256
        );
    }
    println!("Catalog publisher authentication: not checked by this command");
    println!("No package was downloaded, extracted, or installed.");
    ExitCode::SUCCESS
}

fn run(args: Vec<OsString>) -> ExitCode {
    if args.is_empty() {
        print_usage();
        eprintln!("deku-pkg: missing command");
        return ExitCode::from(2);
    }

    let Some(command) = args[0].to_str() else {
        eprintln!("deku-pkg: command must be valid UTF-8");
        return ExitCode::from(2);
    };

    if command == "--help" || command == "-h" {
        if args.len() != 1 {
            print_usage();
            eprintln!("deku-pkg: --help does not accept additional arguments");
            return ExitCode::from(2);
        }
        print_usage();
        return ExitCode::SUCCESS;
    }
    if command == "--version" {
        if args.len() != 1 {
            print_usage();
            eprintln!("deku-pkg: --version does not accept additional arguments");
            return ExitCode::from(2);
        }
        println!("deku-pkg {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    if command == "plan" {
        return run_plan(&args);
    }
    if !matches!(command, "inspect" | "verify" | "files") {
        print_usage();
        eprintln!("deku-pkg: unsupported command: {command}");
        return ExitCode::from(2);
    }
    if args.len() != 2 {
        print_usage();
        eprintln!("deku-pkg: {command} requires exactly one archive path");
        return ExitCode::from(2);
    }

    let path = PathBuf::from(&args[1]);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("deku-pkg: cannot open {}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    };
    let verified = match inspect_archive(&mut BufReader::new(file)) {
        Ok(archive) => archive,
        Err(error) => {
            eprintln!(
                "deku-pkg: archive verification failed for {}: {error}",
                path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    match command {
        "inspect" => print_summary(
            verified.archive_size,
            verified.payload_size,
            &verified.manifest,
        ),
        "verify" => {
            println!(
                "Verified {} {} ({}; {} bytes; all file digests match).",
                verified.manifest.package.name,
                verified.manifest.package.version,
                verified.manifest.package.architecture,
                verified.archive_size
            );
            println!("Publisher authentication: not provided by the archive format");
        }
        "files" => {
            for entry in &verified.manifest.files {
                let kind = match entry.kind {
                    PackageFileKind::File => "file",
                    PackageFileKind::Directory => "directory",
                };
                let digest = entry.sha256.as_deref().unwrap_or("-");
                println!(
                    "{kind:9} {:03o} {:>10} {} {}",
                    entry.mode, entry.size, digest, entry.path
                );
            }
        }
        _ => unreachable!("command was validated before archive access"),
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_root_constraints_without_ambiguity() {
        let parsed = parse_root_requirement("libc>=2.0-0,<3.0-0").expect("valid root");
        assert_eq!(parsed.name, "libc");
        assert_eq!(parsed.constraints.len(), 2);
    }

    #[test]
    fn rejects_empty_and_malformed_root_constraints() {
        for invalid in ["", ">=1.0", "libc>=1.0,", "libc==1.0", "libc >=1.0"] {
            assert!(parse_root_requirement(invalid).is_err(), "{invalid}");
        }
    }
}

fn main() -> ExitCode {
    run(env::args_os().skip(1).collect())
}
