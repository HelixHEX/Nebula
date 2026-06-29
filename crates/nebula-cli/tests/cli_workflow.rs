use assert_cmd::Command;
use assert_fs::prelude::*;
use predicates::prelude::*;

fn neb() -> Command {
    Command::cargo_bin("neb").expect("neb binary should build")
}

#[test]
fn status_detects_edits_without_manual_dirty_marking() {
    let temp = assert_fs::TempDir::new().unwrap();
    let repo = temp.child("repo");
    repo.create_dir_all().unwrap();

    neb()
        .current_dir(repo.path())
        .arg("init")
        .assert()
        .success();
    repo.child("app.txt").write_str("hello nebula\n").unwrap();

    neb()
        .current_dir(repo.path())
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains("1 added"));

    neb()
        .current_dir(repo.path())
        .args(["--json", "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"path\": \"app.txt\""));
}

#[test]
fn local_bundle_clone_materializes_binary_files() {
    let temp = assert_fs::TempDir::new().unwrap();
    let repo = temp.child("repo");
    let clone = temp.child("clone");
    repo.create_dir_all().unwrap();
    clone.create_dir_all().unwrap();

    neb()
        .current_dir(repo.path())
        .arg("init")
        .assert()
        .success();
    repo.child("bin.dat")
        .write_binary(&[0, 159, 146, 150, 255, 10])
        .unwrap();
    neb()
        .current_dir(repo.path())
        .arg("save")
        .assert()
        .success();
    neb()
        .current_dir(repo.path())
        .args(["remote", "add", "origin", "../bundle.json"])
        .assert()
        .success();
    neb()
        .current_dir(repo.path())
        .args(["push", "origin"])
        .assert()
        .success();

    neb()
        .current_dir(clone.path())
        .args(["clone", "../bundle.json"])
        .assert()
        .success();

    clone.child("bin.dat").assert(predicate::path::exists());
    clone
        .child("bin.dat")
        .assert([0, 159, 146, 150, 255, 10].as_slice());
}

#[test]
fn auth_login_status_and_logout_use_explicit_dev_store() {
    let temp = assert_fs::TempDir::new().unwrap();
    let store = temp.child("credentials");
    store.create_dir_all().unwrap();

    neb()
        .env("NEBULA_AUTH_PLAINTEXT_STORE", "1")
        .env("NEBULA_CREDENTIAL_STORE_DIR", store.path())
        .args([
            "auth",
            "login",
            "--registry-url",
            "https://registry.example.test",
            "--token",
            "neb_test_token",
            "--org",
            "org_a",
            "--repository",
            "repo_a",
            "--scope",
            "nebula.repository:sync_objects",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("plaintext-dev"));

    neb()
        .env("NEBULA_CREDENTIAL_STORE_DIR", store.path())
        .args([
            "--json",
            "auth",
            "status",
            "--registry-url",
            "https://registry.example.test",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"authenticated\": true"));

    neb()
        .env("NEBULA_CREDENTIAL_STORE_DIR", store.path())
        .args([
            "auth",
            "logout",
            "--registry-url",
            "https://registry.example.test",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Removed Nebula registry credential",
        ));
}

#[test]
fn auth_token_create_reports_missing_registry_credential() {
    let temp = assert_fs::TempDir::new().unwrap();
    let store = temp.child("credentials");
    store.create_dir_all().unwrap();

    neb()
        .env("NEBULA_CREDENTIAL_STORE_DIR", store.path())
        .args([
            "auth",
            "token",
            "create",
            "ci",
            "--registry-url",
            "https://registry.example.test",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no credential for https://registry.example.test",
        ));
}
