pub mod intrinsic;
pub mod semantic;

use std::collections::HashSet;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use chrono::Utc;
use openvex::Metadata;
use openvex::OpenVex;
use openvex::Statement;
use openvex::Status;

use crate::client::intrinsic::IntrinsicGuacClient;
use crate::client::semantic::SemanticGuacClient;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Purl parsing error: {0}")]
    Purl(#[from] packageurl::Error),
    #[error("Http request error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("GraphQL response error: {}", format_graphql_message(.0))]
    GraphQL(Vec<graphql_client::Error>),
}

fn format_graphql_message(inner: &Vec<graphql_client::Error>) -> String {
    if inner.is_empty() {
        format!("<unspecified>")
    } else {
        format!("{:#?}", inner)
    }
}

#[derive(Clone)]
pub struct GuacClient {
    pub(crate) client: reqwest::Client,
    pub(crate) url: String,
}

impl GuacClient {
    pub fn new(url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
        }
    }

    pub fn semantic(&self) -> SemanticGuacClient {
        SemanticGuacClient::new( self )
    }

    pub fn intrinsic(&self) -> IntrinsicGuacClient {
        IntrinsicGuacClient::new( self )
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

/*
pub fn vulns2vex(vulns: Vec<VulnerabilityResult>) -> OpenVex {
    let mut vex = openvex();

    for vuln in vulns {
        let mut products = HashSet::new();
        let status = Status::Affected;
        let justification = None;
        // TODO consider all products?
        products.insert(vuln.packages[0].clone());

        let id = vuln.id();

        //let now_parsed = DateTime::parse_from_rfc3339(&vuln.time_scanned).unwrap();
        let now_parsed = Utc::now(); //TODO fix time problem

        let statement = Statement {
            vulnerability: Some(id.clone()),
            vuln_description: None,
            timestamp: Some(now_parsed),
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

 */
