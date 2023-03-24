use std::{collections::HashSet, sync::atomic::{Ordering, AtomicU64}};

use chrono::{Utc, DateTime};
use graphql_client::{GraphQLQuery, reqwest::post_graphql};
use anyhow::*;
use openvex::{OpenVex, Metadata, Statement, Status};

use self::certify_vuln::{allCertifyVuln, PkgSpec, AllCertifyVulnVulnerability::OSV};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/schema.json",
    query_path = "src/query/certify_vuln.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct CertifyVuln;

pub struct GuacClient {
    client: reqwest::Client,
    url: String,
}

impl GuacClient {
    pub fn new(url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
        }
    }

    pub async fn certify_vuln(&self, pkg: PkgSpec) -> Result<Vec<allCertifyVuln>, anyhow::Error> {
        let variables = certify_vuln::Variables {
            package: Some(pkg)
        };
        let response_body = post_graphql::<CertifyVuln, _>(&self.client, self.url.to_owned(), variables).await?;
        let response_data = response_body.data.with_context(|| "No data found in response");
        Ok(response_data?.certify_vuln)
    }

}

static VERSION: AtomicU64 = AtomicU64::new(1);
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
            version: format!("{}", VERSION.fetch_add(1, Ordering::Relaxed)),
            tooling: Some("Seedwing Policy Engine".to_string()),
            supplier: Some("seedwing.io".to_string()),
        },
        statements: Vec::new(),
    }
}

pub fn vulns2vex(vulns: Vec<allCertifyVuln>) -> OpenVex {
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

        //let now_parsed = DateTime::parse_from_rfc3339(&vuln.time_scanned).unwrap();
        let now_parsed = Utc::now(); //TODO fix time problem

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

    vex
}