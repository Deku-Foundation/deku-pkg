use std::fs;
use std::path::Path;

use deku_pkg_trust::{RepositoryConfig, TrustError};
use tempfile::tempdir;

fn config(root: &Path, datastore: &Path) -> RepositoryConfig {
    RepositoryConfig::new(
        root,
        "https://packages.example.invalid/metadata/",
        "https://packages.example.invalid/targets/",
        datastore,
    )
    .expect("valid test configuration")
}

#[tokio::test]
async fn rejects_directory_instead_of_trusted_root_file() {
    let temp = tempdir().unwrap();
    let datastore = temp.path().join("datastore");
    fs::create_dir(&datastore).unwrap();

    let error = config(temp.path(), &datastore).load().await.unwrap_err();
    assert!(matches!(error, TrustError::InvalidTrustedRootPath));
}

#[tokio::test]
async fn rejects_empty_trusted_root_metadata() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root.json");
    let datastore = temp.path().join("datastore");
    fs::write(&root, []).unwrap();
    fs::create_dir(&datastore).unwrap();

    let error = config(&root, &datastore).load().await.unwrap_err();
    assert!(matches!(error, TrustError::TrustedRootEmpty));
}

#[tokio::test]
async fn rejects_oversized_trusted_root_before_network_access() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root.json");
    let datastore = temp.path().join("datastore");
    fs::write(&root, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    fs::create_dir(&datastore).unwrap();

    let error = config(&root, &datastore).load().await.unwrap_err();
    assert!(matches!(error, TrustError::TrustedRootTooLarge { .. }));
}

#[tokio::test]
async fn requires_existing_datastore_before_network_access() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root.json");
    let datastore = temp.path().join("missing-datastore");
    fs::write(&root, b"not valid TUF metadata").unwrap();

    let error = config(&root, &datastore).load().await.unwrap_err();
    assert!(matches!(error, TrustError::DatastoreUnavailable(_)));
}

#[tokio::test]
async fn rejects_regular_file_as_datastore() {
    let temp = tempdir().unwrap();
    let root = temp.path().join("root.json");
    let datastore = temp.path().join("datastore-file");
    fs::write(&root, b"not valid TUF metadata").unwrap();
    fs::write(&datastore, b"not a directory").unwrap();

    let error = config(&root, &datastore).load().await.unwrap_err();
    assert!(matches!(error, TrustError::DatastoreUnavailable(_)));
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_symlink_trusted_root() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().unwrap();
    let real_root = temp.path().join("real-root.json");
    let root_link = temp.path().join("root.json");
    let datastore = temp.path().join("datastore");
    fs::write(&real_root, b"not valid TUF metadata").unwrap();
    symlink(&real_root, &root_link).unwrap();
    fs::create_dir(&datastore).unwrap();

    let error = config(&root_link, &datastore).load().await.unwrap_err();
    assert!(matches!(error, TrustError::InvalidTrustedRootPath));
}

#[cfg(unix)]
#[tokio::test]
async fn rejects_symlink_datastore() {
    use std::os::unix::fs::symlink;

    let temp = tempdir().unwrap();
    let root = temp.path().join("root.json");
    let real_datastore = temp.path().join("real-datastore");
    let datastore_link = temp.path().join("datastore-link");
    fs::write(&root, b"not valid TUF metadata").unwrap();
    fs::create_dir(&real_datastore).unwrap();
    symlink(&real_datastore, &datastore_link).unwrap();

    let error = config(&root, &datastore_link).load().await.unwrap_err();
    assert!(matches!(error, TrustError::DatastoreUnavailable(_)));
}
