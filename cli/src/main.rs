

use guac_rs::{client::GuacClient, vuln::{certify_vuln::PkgSpec, vulns2vex}};
use packageurl::PackageUrl;
use anyhow::*;
use std::str::FromStr;

use colored_json::prelude::*;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let purl = PackageUrl::from_str("pkg:pypi/django")?;
    //let purl = PackageUrl::from_str("pkg:maven/io.vertx/vertx-web@4.3.7")?;

    let pkg = PkgSpec {
        id: Some(purl.name().to_string()), //TODO use proper id
        type_: Some(purl.ty().to_string()),
        namespace: purl.namespace().map(|s| s.to_string()),
        name: Some(purl.name().to_string()),
        subpath: purl.subpath().map(|s|s.to_string()),
        version: purl.version().map(|s|s.to_string()),
        qualifiers: None, //TODO fix qualifiers
        match_only_empty_qualifiers: Some(false),
    };

    let guac = GuacClient::new("http://localhost:8080/query".to_string());
    let vulns = guac.certify_vuln(pkg).await?;

    let vex = vulns2vex(vulns);

    let out = serde_json::to_string(&vex)?.to_colored_json_auto()?;

    println!("{}", out);
    Ok(())

}
