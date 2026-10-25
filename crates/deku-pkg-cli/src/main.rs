use deku_pkg_core::package_archive::{PackageFileKind, inspect_archive};
use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use std::process::ExitCode;

fn print_usage() {
    println!(
        "Usage:\n  deku-pkg inspect <archive>\n  deku-pkg verify <archive>\n  deku-pkg files <archive>\n  deku-pkg --version"
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

fn main() -> ExitCode {
    run(env::args_os().skip(1).collect())
}
