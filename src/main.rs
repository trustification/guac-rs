use std::collections::HashSet;

use chrono::{Utc, DateTime};
use guac_rs::client::{GuacClient, certify_vuln::*, certify_vuln::AllCertifyVulnVulnerability::OSV};
use openvex::{Metadata, OpenVex, Status, Statement};
use packageurl::PackageUrl;
use reqwest::Client;
use graphql_client::{reqwest::post_graphql, GraphQLQuery};
use anyhow::*;
use std::str::FromStr;


// #[derive(GraphQLQuery)]
// #[graphql(
//     schema_path = "src/schema.json",
//     query_path = "src/query/certify_vuln.gql",
//     response_derives = "Debug, Serialize, Deserialize"
// )]
// pub struct CertifyVuln;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {

    let purl = PackageUrl::from_str("pkg:pypi/django")?;
    //let purl = PackageUrl::from_str("pkg:maven/io.vertx/vertx-web@4.3.7")?;

    println!("{:?} - {:?} - {:?}", purl.ty(), purl.namespace(), purl.name());

    let pkg = PkgSpec {
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

    let mut vex = openvex();

    for vuln in vulns {
        let mut products = HashSet::new();
        let status = Status::Affected;
        let justification = None;
        products.insert(vuln.package.namespaces[0].names[0].name.clone());
        let id = match vuln.vulnerability {
            OSV(osv) => {
                osv.osv_id[0].id.clone()
            },
            _ => {
                String::from("NOT_SET")
            }
        };

        let now_parsed = DateTime::parse_from_rfc3339(&vuln.time_scanned).unwrap();

        let statement = Statement {
          vulnerability: Some(id.clone()),
            vuln_description: None,
            timestamp: Some(now_parsed.into()),
            products: products.drain().collect(),
            subcomponents: Vec::new(),
            status,
            status_notes: Some("Vulnerabilities reported by Guac".into()),
            justification,
            impact_statement: None,
            action_statement: Some(format!(
                "Review {} for details on the appropriate action",
                id.clone()
            )),
            action_statement_timestamp: Some(Utc::now()),
        };
        vex.statements.push(statement);
    }

    println!("{:#?}", vex);
    Ok(())

}


fn openvex() -> OpenVex {
    OpenVex {
        metadata: Metadata {
            context: "https://openvex.dev/ns".to_string(),
            id: format!(
                "https://seedwing.io/ROOT/generated/{}",
                uuid::Uuid::new_v4()
            ),
            author: "Seedwing Policy Engine".to_string(),
            role: "Document Creator".to_string(),
            timestamp: Some(Utc::now()),
            version: format!("{}", "1"),
            tooling: Some("Seedwing Policy Engine".to_string()),
            supplier: Some("seedwing.io".to_string()),
        },
        statements: Vec::new(),
    }
}