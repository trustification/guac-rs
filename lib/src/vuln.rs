use std::{
    collections::HashSet,
    sync::atomic::{AtomicU64, Ordering},
};

use chrono::Utc;
use graphql_client::GraphQLQuery;
use openvex::{Metadata, OpenVex, Statement, Status};
use packageurl::PackageUrl;
use std::str::FromStr;

use self::certify_vuln_q1::{
    allCertifyVulnTree, AllCertifyVulnTreeVulnerability::OSV, PackageQualifierSpec, PkgSpec,
};

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/schema.json",
    query_path = "src/query/certify_vuln.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct CertifyVulnQ1;

impl TryFrom<&str> for PkgSpec {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let purl = PackageUrl::from_str(s)?;
        let mut qualifiers = Vec::new();
        for (key, value) in purl.qualifiers().iter() {
            qualifiers.push(PackageQualifierSpec {
                key: key.to_string(),
                value: Some(value.to_string()),
            })
        }

        Ok(PkgSpec {
            id: None,
            type_: Some(purl.ty().to_string()),
            namespace: purl.namespace().map(|s| s.to_string()),
            name: Some(purl.name().to_string()),
            subpath: purl.subpath().map(|s| s.to_string()),
            version: purl.version().map(|s| s.to_string()),
            qualifiers: if qualifiers.is_empty() {
                None
            } else {
                Some(qualifiers)
            },
            match_only_empty_qualifiers: Some(false),
        })
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

pub fn vulns2vex(vulns: Vec<allCertifyVulnTree>) -> OpenVex {
    let mut vex = openvex();

    for vuln in vulns {
        let mut products = HashSet::new();
        let status = Status::Affected;
        let justification = None;
        products.insert(vuln.package.namespaces[0].names[0].name.clone());
        let id = match vuln.vulnerability {
            OSV(osv) => osv.osv_id.clone(),
            _ => String::from("NOT_SET"),
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
