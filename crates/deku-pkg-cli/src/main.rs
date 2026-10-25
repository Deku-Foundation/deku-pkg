use deku_pkg_core::content_store::ContentStore;
use deku_pkg_core::package_archive::PackageInfo;
use deku_pkg_core::package_archive::{MAX_PACKAGE_ARCHIVE_BYTES, PackageFileKind, inspect_archive};
use deku_pkg_core::package_builder::write_archive_from_directory;
use deku_pkg_core::solver::{DependencyRequirement, VersionConstraint};
use deku_pkg_core::solver_catalog::SolverCatalog;
use deku_pkg_trust::RepositoryConfig;
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

fn print_usage() {
    println!(
        "Usage:\n  deku-pkg pack <destdir> <output.dpak> <name> <version> <architecture> <abi> <license> [dependency...]\n  deku-pkg inspect <archive>\n  deku-pkg verify <archive>\n  deku-pkg files <archive>\n  deku-pkg plan <catalog.json> <x86_64|aarch64> <package[>=version,...]>...\n  deku-pkg trusted-plan <root.json> <metadata-url> <targets-url> <datastore> <staging> <catalog-target> <x86_64|aarch64> <package[>=version,...]>...\n  deku-pkg trusted-fetch-plan <root.json> <metadata-url> <targets-url> <datastore> <staging> <store> <catalog-target> <x86_64|aarch64> <package[>=version,...]>...\n  deku-pkg --version"
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
    println!("Archive SHA-256: {archive_sha256}");
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
    if args.len() < 5 {
        print_usage();
        eprintln!(
            "deku-pkg: plan requires a catalog, target architecture, ABI, and at least one package"
        );
        return ExitCode::from(2);
    }

    let architecture = match utf8_argument(args, 2, "target architecture") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let target_abi = match utf8_argument(args, 3, "target ABI") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let roots = match args[4..]
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
    let catalog = match read_bounded_catalog(&path) {
        Ok(catalog) => catalog,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::FAILURE;
        }
    };
    let plan = match catalog.plan(&roots, architecture, target_abi) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("deku-pkg: dependency resolution failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("Target architecture: {architecture}");
    println!("Target ABI: {target_abi}");
    println!("Packages in plan: {}", plan.packages.len());
    println!("Resolver states explored: {}", plan.explored_states);
    for package in &plan.packages {
        println!(
            "{} {} {} ABI:{} {} sha256:{}",
            package.name,
            package.version,
            package.architecture,
            package.abi,
            package.artifact.file,
            package.artifact.sha256
        );
    }
    println!("Catalog publisher authentication: not checked by this command");
    println!("No package was downloaded, extracted, or installed.");
    ExitCode::SUCCESS
}

fn read_bounded_catalog(path: &std::path::Path) -> Result<SolverCatalog, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect catalog target {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("verified catalog target must be a regular non-symlink file".to_string());
    }
    const MAX_CATALOG_BYTES: u64 = 16 * 1024 * 1024;
    if metadata.len() > MAX_CATALOG_BYTES {
        return Err(format!(
            "catalog target is {} bytes; maximum is {MAX_CATALOG_BYTES}",
            metadata.len()
        ));
    }

    let file = File::open(path)
        .map_err(|error| format!("cannot open catalog target {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    BufReader::new(file)
        .take(MAX_CATALOG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read catalog target {}: {error}", path.display()))?;
    SolverCatalog::from_json(&bytes).map_err(|error| format!("invalid solver catalog: {error}"))
}

fn utf8_argument<'a>(args: &'a [OsString], index: usize, label: &str) -> Result<&'a str, String> {
    args[index]
        .to_str()
        .ok_or_else(|| format!("{label} must be valid UTF-8"))
}

fn run_trusted_plan(args: &[OsString]) -> ExitCode {
    if args.len() < 10 {
        print_usage();
        eprintln!(
            "deku-pkg: trusted-plan requires root, metadata URL, targets URL, datastore, staging, catalog target, architecture, ABI, and at least one package"
        );
        return ExitCode::from(2);
    }

    let metadata_url = match utf8_argument(args, 2, "metadata URL") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let targets_url = match utf8_argument(args, 3, "targets URL") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let catalog_target = match utf8_argument(args, 6, "catalog target") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let architecture = match utf8_argument(args, 7, "target architecture") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let target_abi = match utf8_argument(args, 8, "target ABI") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };

    let roots = match args[9..]
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

    let config = match RepositoryConfig::new(
        PathBuf::from(&args[1]),
        metadata_url,
        targets_url,
        PathBuf::from(&args[4]),
    ) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("deku-pkg: invalid trusted repository configuration: {error}");
            return ExitCode::from(2);
        }
    };

    let staging = PathBuf::from(&args[5]);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("deku-pkg: cannot initialize async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    const MAX_CATALOG_TARGET_BYTES: u64 = 16 * 1024 * 1024;
    let verified_target = runtime.block_on(async {
        let repository = config.load().await?;
        let target_count = repository.target_count();
        let catalog_info = repository.target_info(catalog_target)?;
        if catalog_info.length > MAX_CATALOG_TARGET_BYTES {
            return Err(deku_pkg_trust::TrustError::TargetTooLarge {
                name: catalog_info.name,
                size: catalog_info.length,
                limit: MAX_CATALOG_TARGET_BYTES,
            });
        }
        let path = repository
            .download_verified_target(catalog_target, &staging)
            .await?;
        Ok::<_, deku_pkg_trust::TrustError>((repository, target_count, path))
    });
    let (repository, target_count, catalog_path) = match verified_target {
        Ok(result) => result,
        Err(error) => {
            eprintln!("deku-pkg: TUF repository verification failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    let catalog = match read_bounded_catalog(&catalog_path) {
        Ok(catalog) => catalog,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::FAILURE;
        }
    };
    let plan = match catalog.plan(&roots, architecture, target_abi) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("deku-pkg: dependency resolution failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    // Check that every selected artifact is part of the same authenticated
    // TUF view as the catalog, before presenting this as a trusted plan.
    for package in &plan.packages {
        let target_info = match repository.target_info(&package.artifact.file) {
            Ok(info) => info,
            Err(error) => {
                eprintln!(
                    "deku-pkg: planned artifact {} is not authorized by TUF: {error}",
                    package.artifact.file
                );
                return ExitCode::FAILURE;
            }
        };
        if target_info.length > MAX_PACKAGE_ARCHIVE_BYTES {
            eprintln!(
                "deku-pkg: artifact {} exceeds the native archive size limit ({} > {})",
                target_info.name, target_info.length, MAX_PACKAGE_ARCHIVE_BYTES
            );
            return ExitCode::FAILURE;
        }
        if target_info.sha256 != package.artifact.sha256 {
            eprintln!(
                "deku-pkg: SHA-256 mismatch between catalog and signed TUF target metadata for {}",
                package.artifact.file
            );
            return ExitCode::FAILURE;
        }
    }

    println!("Repository metadata: TUF verified; expiry and rollback checks enforced by tough");
    println!("Verified top-level repository targets: {target_count}");
    println!("Catalog target: {catalog_target}");
    println!("Target architecture: {architecture}");
    println!("Target ABI: {target_abi}");
    println!("Packages in plan: {}", plan.packages.len());
    println!("Resolver states explored: {}", plan.explored_states);
    for package in &plan.packages {
        println!(
            "{} {} {} ABI:{} {} sha256:{}",
            package.name,
            package.version,
            package.architecture,
            package.abi,
            package.artifact.file,
            package.artifact.sha256
        );
    }
    println!(
        "All planned artifacts exist in signed TUF metadata; signed SHA-256 values agree with the catalog."
    );
    println!(
        "Package artifact bytes have not been downloaded or verified in the content store by this command."
    );
    println!("No package was extracted or installed.");
    ExitCode::SUCCESS
}

struct DigestWriter<'a> {
    inner: &'a mut File,
    hasher: Sha256,
    written: u64,
}

impl<'a> DigestWriter<'a> {
    fn new(inner: &'a mut File) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }

    fn finish(self) -> (u64, String) {
        (self.written, format!("{:x}", self.hasher.finalize()))
    }
}

impl Write for DigestWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        self.written = self.written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn create_pack_temp(parent: &std::path::Path) -> Result<(PathBuf, File), String> {
    const MAX_ATTEMPTS: u32 = 32;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    for attempt in 0..MAX_ATTEMPTS {
        let path = parent.join(format!(
            ".deku-pack-{}-{timestamp}-{attempt}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "cannot create temporary package {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Err("too many temporary output path collisions".to_string())
}

fn set_pack_output_permissions(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
    }
    #[cfg(not(unix))]
    {
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_readonly(false);
        fs::set_permissions(path, permissions)
    }
}

fn run_pack(args: &[OsString]) -> ExitCode {
    if args.len() < 8 {
        print_usage();
        eprintln!(
            "deku-pkg: pack requires DESTDIR, output, name, version, architecture, ABI, and license"
        );
        return ExitCode::from(2);
    }

    let package_name = match utf8_argument(args, 3, "package name") {
        Ok(value) => value.to_string(),
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let version = match utf8_argument(args, 4, "package version") {
        Ok(value) => value.to_string(),
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let architecture = match utf8_argument(args, 5, "package architecture") {
        Ok(value) => value.to_string(),
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let abi = match utf8_argument(args, 6, "Deku ABI") {
        Ok(value) => value.to_string(),
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let license = match utf8_argument(args, 7, "license expression") {
        Ok(value) => value.to_string(),
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let dependencies = match args[8..]
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| "dependency names must be valid UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(dependencies) => dependencies,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };

    let source_root = PathBuf::from(&args[1]);
    let output_requested = PathBuf::from(&args[2]);
    let Some(output_name) = output_requested.file_name() else {
        eprintln!("deku-pkg: output must name a file");
        return ExitCode::from(2);
    };
    let requested_parent = output_requested
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let parent_metadata = match fs::symlink_metadata(requested_parent) {
        Ok(metadata) => metadata,
        Err(error) => {
            eprintln!(
                "deku-pkg: cannot inspect output directory {}: {error}",
                requested_parent.display()
            );
            return ExitCode::FAILURE;
        }
    };
    if !parent_metadata.file_type().is_dir() || parent_metadata.file_type().is_symlink() {
        eprintln!("deku-pkg: output parent must be a real directory");
        return ExitCode::FAILURE;
    }
    let output_parent = match fs::canonicalize(requested_parent) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("deku-pkg: cannot canonicalize output directory: {error}");
            return ExitCode::FAILURE;
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = match fs::metadata(&output_parent) {
            Ok(metadata) => metadata,
            Err(error) => {
                eprintln!("deku-pkg: cannot inspect canonical output directory: {error}");
                return ExitCode::FAILURE;
            }
        };
        if metadata.permissions().mode() & 0o022 != 0 {
            eprintln!("deku-pkg: output directory must not be group or world writable");
            return ExitCode::FAILURE;
        }
    }
    let destination = output_parent.join(output_name);
    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            eprintln!(
                "deku-pkg: refusing to overwrite existing output {}",
                destination.display()
            );
            return ExitCode::FAILURE;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            eprintln!("deku-pkg: cannot inspect output path: {error}");
            return ExitCode::FAILURE;
        }
    }

    let package = PackageInfo {
        name: package_name,
        version,
        architecture,
        abi,
        license,
        dependencies,
    };
    let (temporary, mut file) = match create_pack_temp(&output_parent) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut digest_writer = DigestWriter::new(&mut file);
    let built = write_archive_from_directory(&source_root, package, &mut digest_writer);
    let (bytes_written, archive_sha256) = digest_writer.finish();
    let archive_size = match built {
        Ok(size) => size,
        Err(error) => {
            drop(file);
            let _ = fs::remove_file(&temporary);
            eprintln!("deku-pkg: package build failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    if bytes_written != archive_size {
        drop(file);
        let _ = fs::remove_file(&temporary);
        eprintln!("deku-pkg: package writer reported inconsistent output length");
        return ExitCode::FAILURE;
    }
    if let Err(error) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(&temporary);
        eprintln!("deku-pkg: cannot sync built archive: {error}");
        return ExitCode::FAILURE;
    }
    drop(file);

    if let Err(error) = set_pack_output_permissions(&temporary) {
        let _ = fs::remove_file(&temporary);
        eprintln!("deku-pkg: cannot set package output permissions: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = File::open(&temporary).and_then(|file| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        eprintln!("deku-pkg: cannot sync package output permissions: {error}");
        return ExitCode::FAILURE;
    }

    if let Err(error) = fs::hard_link(&temporary, &destination) {
        let _ = fs::remove_file(&temporary);
        eprintln!(
            "deku-pkg: cannot publish package without overwriting {}: {error}",
            destination.display()
        );
        return ExitCode::FAILURE;
    }
    if let Err(error) = File::open(&output_parent).and_then(|directory| directory.sync_all()) {
        let _ = fs::remove_file(&destination);
        let _ = fs::remove_file(&temporary);
        eprintln!("deku-pkg: cannot sync output directory: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = fs::remove_file(&temporary) {
        eprintln!("deku-pkg: package was published but temporary-file cleanup failed: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = File::open(&output_parent).and_then(|directory| directory.sync_all()) {
        eprintln!("deku-pkg: package published but directory sync failed: {error}");
        return ExitCode::FAILURE;
    }

    println!("Built native Deku package: {}", destination.display());
    println!("Archive bytes: {archive_size}");
    println!("Package artifact: deterministic, internal file digests recorded");
    println!("No package was installed and no live system root was changed.");
    ExitCode::SUCCESS
}

fn run_trusted_fetch_plan(args: &[OsString]) -> ExitCode {
    if args.len() < 11 {
        print_usage();
        eprintln!(
            "deku-pkg: trusted-fetch-plan requires root, metadata URL, targets URL, datastore, staging, store, catalog target, architecture, ABI, and at least one package"
        );
        return ExitCode::from(2);
    }

    let metadata_url = match utf8_argument(args, 2, "metadata URL") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let targets_url = match utf8_argument(args, 3, "targets URL") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let catalog_target = match utf8_argument(args, 7, "catalog target") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let architecture = match utf8_argument(args, 8, "target architecture") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };
    let target_abi = match utf8_argument(args, 9, "target ABI") {
        Ok(value) => value,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::from(2);
        }
    };

    let roots = match args[10..]
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

    let config = match RepositoryConfig::new(
        PathBuf::from(&args[1]),
        metadata_url,
        targets_url,
        PathBuf::from(&args[4]),
    ) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("deku-pkg: invalid trusted repository configuration: {error}");
            return ExitCode::from(2);
        }
    };

    let staging = PathBuf::from(&args[5]);
    let store = match ContentStore::open(PathBuf::from(&args[6])) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("deku-pkg: cannot open protected content store: {error}");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("deku-pkg: cannot initialize async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    const MAX_CATALOG_TARGET_BYTES: u64 = 16 * 1024 * 1024;
    let verified_target = runtime.block_on(async {
        let repository = config.load().await?;
        let target_count = repository.target_count();
        let catalog_info = repository.target_info(catalog_target)?;
        if catalog_info.length > MAX_CATALOG_TARGET_BYTES {
            return Err(deku_pkg_trust::TrustError::TargetTooLarge {
                name: catalog_info.name,
                size: catalog_info.length,
                limit: MAX_CATALOG_TARGET_BYTES,
            });
        }
        let path = repository
            .download_verified_target(catalog_target, &staging)
            .await?;
        Ok::<_, deku_pkg_trust::TrustError>((repository, target_count, path))
    });
    let (repository, target_count, catalog_path) = match verified_target {
        Ok(result) => result,
        Err(error) => {
            eprintln!("deku-pkg: TUF repository verification failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    let catalog = match read_bounded_catalog(&catalog_path) {
        Ok(catalog) => catalog,
        Err(error) => {
            eprintln!("deku-pkg: {error}");
            return ExitCode::FAILURE;
        }
    };
    let plan = match catalog.plan(&roots, architecture, target_abi) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("deku-pkg: dependency resolution failed: {error}");
            return ExitCode::FAILURE;
        }
    };

    println!("Repository metadata: TUF verified; expiry and rollback checks enforced by tough");
    println!("Verified top-level repository targets: {target_count}");
    println!("Catalog target: {catalog_target}");
    println!("Target architecture: {architecture}");
    println!("Target ABI: {target_abi}");
    println!("Packages in plan: {}", plan.packages.len());
    println!("Resolver states explored: {}", plan.explored_states);

    let mut stored_count = 0usize;
    for package in &plan.packages {
        let target_info = match repository.target_info(&package.artifact.file) {
            Ok(info) => info,
            Err(error) => {
                eprintln!(
                    "deku-pkg: planned artifact {} is not authorized by TUF: {error}",
                    package.artifact.file
                );
                return ExitCode::FAILURE;
            }
        };
        if target_info.length > MAX_PACKAGE_ARCHIVE_BYTES {
            eprintln!(
                "deku-pkg: artifact {} exceeds the native archive size limit ({} > {})",
                target_info.name, target_info.length, MAX_PACKAGE_ARCHIVE_BYTES
            );
            return ExitCode::FAILURE;
        }
        if target_info.sha256 != package.artifact.sha256 {
            eprintln!(
                "deku-pkg: SHA-256 mismatch between catalog and signed TUF target metadata for {}",
                package.artifact.file
            );
            return ExitCode::FAILURE;
        }

        let downloaded = match runtime
            .block_on(repository.download_verified_target(&package.artifact.file, &staging))
        {
            Ok(path) => path,
            Err(error) => {
                eprintln!(
                    "deku-pkg: TUF-verified download failed for {}: {error}",
                    package.artifact.file
                );
                return ExitCode::FAILURE;
            }
        };

        let metadata = match std::fs::symlink_metadata(&downloaded) {
            Ok(metadata) => metadata,
            Err(error) => {
                eprintln!(
                    "deku-pkg: cannot inspect downloaded artifact {}: {error}",
                    package.artifact.file
                );
                return ExitCode::FAILURE;
            }
        };
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            eprintln!(
                "deku-pkg: downloaded target is not a regular non-symlink file: {}",
                package.artifact.file
            );
            return ExitCode::FAILURE;
        }
        if metadata.len() != target_info.length {
            eprintln!(
                "deku-pkg: downloaded length differs from signed TUF metadata for {}",
                package.artifact.file
            );
            return ExitCode::FAILURE;
        }

        let archive = match File::open(&downloaded)
            .map(BufReader::new)
            .map_err(|error| error.to_string())
            .and_then(|mut reader| inspect_archive(&mut reader).map_err(|error| error.to_string()))
        {
            Ok(archive) => archive,
            Err(error) => {
                eprintln!(
                    "deku-pkg: native archive verification failed for {}: {error}",
                    package.artifact.file
                );
                return ExitCode::FAILURE;
            }
        };

        if archive.manifest.package.name != package.name
            || archive.manifest.package.version != package.version.canonical()
            || archive.manifest.package.architecture != package.architecture
            || archive.manifest.package.abi != package.abi
        {
            eprintln!(
                "deku-pkg: archive identity does not match the resolved catalog entry for {}",
                package.artifact.file
            );
            return ExitCode::FAILURE;
        }
        if archive.archive_size != target_info.length
            || archive.archive_size > MAX_PACKAGE_ARCHIVE_BYTES
        {
            eprintln!(
                "deku-pkg: archive size differs from signed metadata or exceeds policy for {}",
                package.artifact.file
            );
            return ExitCode::FAILURE;
        }

        let input = match File::open(&downloaded) {
            Ok(file) => file,
            Err(error) => {
                eprintln!(
                    "deku-pkg: cannot reopen verified artifact {}: {error}",
                    package.artifact.file
                );
                return ExitCode::FAILURE;
            }
        };
        let stored =
            match store.put_reader(input, &package.artifact.sha256, MAX_PACKAGE_ARCHIVE_BYTES) {
                Ok(stored) => stored,
                Err(error) => {
                    eprintln!(
                        "deku-pkg: content-store validation failed for {}: {error}",
                        package.artifact.file
                    );
                    return ExitCode::FAILURE;
                }
            };
        if stored.size != target_info.length {
            eprintln!(
                "deku-pkg: content-store length disagrees with signed metadata for {}",
                package.artifact.file
            );
            return ExitCode::FAILURE;
        }
        if let Err(error) = store.verify_object(&package.artifact.sha256, MAX_PACKAGE_ARCHIVE_BYTES)
        {
            eprintln!(
                "deku-pkg: stored artifact failed re-verification for {}: {error}",
                package.artifact.file
            );
            return ExitCode::FAILURE;
        }

        println!(
            "verified-and-stored {} {} {} sha256:{} path:{}",
            package.name,
            package.version,
            package.architecture,
            stored.sha256,
            stored.path.display()
        );
        stored_count += 1;
    }

    println!("Verified and stored package artifacts: {stored_count}");
    println!("No package was extracted or installed; system state is unchanged.");
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
    if command == "trusted-plan" {
        return run_trusted_plan(&args);
    }
    if command == "trusted-fetch-plan" {
        return run_trusted_fetch_plan(&args);
    }
    if command == "pack" {
        return run_pack(&args);
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
