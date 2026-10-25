use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestProject(PathBuf);

impl TestProject {
    fn new() -> Self {
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "deku-pkg-cli-pack-test-{}-{count}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create test project root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("protect test project root");
        }
        Self(root)
    }
}

impl Drop for TestProject {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_pack(root: &TestProject, destdir: &std::path::Path, output: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_deku-pkg"))
        .arg("pack")
        .arg(destdir)
        .arg(output)
        .arg("fixture")
        .arg("1.0-1")
        .arg("x86_64")
        .arg("deku1-linux-gnu")
        .arg("MIT")
        .current_dir(&root.0)
        .output()
        .expect("run package builder CLI")
}

#[test]
fn pack_cli_emits_a_verifiable_archive_and_refuses_overwrite() {
    let project = TestProject::new();
    let destdir = project.0.join("destdir");
    let output_dir = project.0.join("out");
    let executable_dir = destdir.join("usr").join("bin");
    fs::create_dir_all(&executable_dir).expect("create package DESTDIR");
    fs::create_dir(&output_dir).expect("create output directory");
    let executable = executable_dir.join("fixture");
    fs::write(&executable, b"hello from a Deku native package").expect("write package file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
            .expect("mark package file executable");
    }

    let archive_path = output_dir.join("fixture-1.0-1-x86_64.dpak");
    let result = run_pack(&project, &destdir, &archive_path);
    assert!(
        result.status.success(),
        "pack failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let archive_bytes = fs::read(&archive_path).expect("read package archive");
    let digest = format!("{:x}", Sha256::digest(&archive_bytes));
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(stdout.contains(&format!("Archive SHA-256: {digest}")));
    assert!(stdout.contains("No package was installed"));

    let inspected = Command::new(env!("CARGO_BIN_EXE_deku-pkg"))
        .arg("inspect")
        .arg(&archive_path)
        .current_dir(&project.0)
        .output()
        .expect("run archive inspector");
    assert!(
        inspected.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("fixture"));
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("deku1-linux-gnu"));

    let repeated = run_pack(&project, &destdir, &archive_path);
    assert!(
        !repeated.status.success(),
        "existing output must not be overwritten"
    );
    assert_eq!(
        fs::read(&archive_path).expect("read preserved package"),
        archive_bytes
    );
}

#[test]
fn pack_cli_rejects_symlink_payloads_without_publishing_output() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let project = TestProject::new();
        let destdir = project.0.join("destdir");
        let output_dir = project.0.join("out");
        fs::create_dir(&destdir).expect("create DESTDIR");
        fs::create_dir(&output_dir).expect("create output directory");
        fs::write(project.0.join("target"), b"target").expect("write symlink target");
        symlink(project.0.join("target"), destdir.join("linked"))
            .expect("create forbidden payload symlink");

        let archive_path = output_dir.join("invalid.dpak");
        let result = run_pack(&project, &destdir, &archive_path);
        assert!(!result.status.success());
        assert!(!archive_path.exists());
        assert!(
            fs::read_dir(&output_dir)
                .expect("list output")
                .next()
                .is_none(),
            "temporary output must be cleaned after failure"
        );
    }
}
