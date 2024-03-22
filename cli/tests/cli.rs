use std::{env, fs};
use tokio::process::Command;

const GUAC_URL: &str = "http://localhost:8085/query";

#[tokio::test]
async fn test_cli_should_fail() {
    let output = Command::new(env!("CARGO_BIN_EXE_guac")).output().await.unwrap();
    // [expected], [output]
    assert_eq!(Some(2), output.status.code());
}

#[tokio::test]
async fn test_query_dependencies() {
    let output = Command::new(env!("CARGO_BIN_EXE_guac"))
        .arg("query")
        .arg("dependencies")
        .arg(format!("-g {}", &GUAC_URL))
        .arg("pkg:rpm/trustification-pkg-A@0.3.0")
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    let expected = "[]\n";
    assert_eq!(expected, out);
}

#[tokio::test]
async fn test_query_dependents() {
    let output = Command::new(env!("CARGO_BIN_EXE_guac"))
        .arg("query")
        .arg("dependents")
        .arg(format!("-g {}", &GUAC_URL))
        .arg("pkg:rpm/trustification-pkg-A@0.3.0")
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    assert!(out.contains("trustification-pkg-B"));
}

#[tokio::test]
async fn test_query_bad() {
    let output = Command::new(env!("CARGO_BIN_EXE_guac"))
        .arg("query")
        .arg("bad")
        .arg(format!("-g {}", &GUAC_URL))
        .arg("pkg:rpm/trustification-certify-bad@0.3.0")
        .output()
        .await
        .unwrap();

    let out = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success());
    assert!(out.contains("test-justification"));
}

#[tokio::test]
async fn test_query_good() {
    let output = Command::new(env!("CARGO_BIN_EXE_guac"))
        .arg("query")
        .arg("good")
        .arg(format!("-g {}", &GUAC_URL))
        .arg("pkg:rpm/trustification-certify-good@0.3.0")
        .output()
        .await
        .unwrap();

    let out = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success());
    assert!(out.contains("test-justification"));
}

#[tokio::test]
async fn test_query_packages() {
    let output = Command::new(env!("CARGO_BIN_EXE_guac"))
        .arg("query")
        .arg("packages")
        .arg(format!("-g {}", &GUAC_URL))
        .arg("pkg:rpm/trustification-test")
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let out = String::from_utf8(output.stdout).unwrap();
    assert!(out.contains("0.3.0"));
    assert!(out.contains("0.3.1"));
}

#[tokio::test]
async fn test_query_vulnerabilities() {
    let output = Command::new(env!("CARGO_BIN_EXE_guac"))
        .arg("query")
        .arg("vulnerabilities")
        .arg(format!("-g {}", &GUAC_URL))
        .arg("pkg:rpm/trustification-certify-good@0.3.0")
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let expected = "";
    let out = String::from_utf8(output.stdout).unwrap();
    assert_eq!(expected, out);
}

#[tokio::test]
async fn test_query_vulnerabilities_vex_enabled() {
    let output = Command::new(env!("CARGO_BIN_EXE_guac"))
        .arg("query")
        .arg("vulnerabilities")
        .arg(format!("-g {}", &GUAC_URL))
        .arg("-v")
        .arg("pkg:rpm/trustification-certify-good@0.3.0")
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let expected = "";
    let out = String::from_utf8(output.stdout).unwrap();
    assert_eq!(expected, out);
}

#[tokio::test]
async fn test_certify_good() {
    let output = Command::new(env!("CARGO_BIN_EXE_guac"))
        .arg("certify")
        .arg("good")
        .arg(format!("-g {}", &GUAC_URL))
        .arg("--justification")
        .arg("lgtm")
        .arg("pkg:rpm/trustification-certify-good@0.3.0")
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let expected = "";
    let out = String::from_utf8(output.stdout).unwrap();
    assert_eq!(expected, out);
}

#[tokio::test]
async fn test_certify_bad() {
    let output = Command::new(env!("CARGO_BIN_EXE_guac"))
        .arg("certify")
        .arg("bad")
        .arg(format!("-g {}", &GUAC_URL))
        .arg("--justification")
        .arg("not good")
        .arg("pkg:rpm/trustification-certify-good@0.3.0")
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let expected = "";
    let out = String::from_utf8(output.stdout).unwrap();
    assert_eq!(expected, out);
}

#[tokio::test]
async fn test_collect_file() {
    let path = fs::canonicalize("../example/seedwing-java-example.bom")
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let output = Command::new(env!("CARGO_BIN_EXE_guac"))
        .arg("collect")
        .arg("file")
        .arg(path.clone())
        .output()
        .await
        .unwrap();

    assert!(output.status.success());
    let expected = format!("Collecting file \"{}\"\n", path);
    let out = String::from_utf8(output.stdout).unwrap();
    assert_eq!(expected, out);
}
