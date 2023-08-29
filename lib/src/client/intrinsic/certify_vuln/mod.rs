use anyhow::Context;
use chrono::Utc;
use graphql_client::reqwest::post_graphql;

use self::ingest::IngestCertifyVuln;
use crate::client::intrinsic::certify_vuln::query::{query_certify_vuln, QueryCertifyVuln};
use crate::client::intrinsic::package::{Package, PkgInputSpec, PkgSpec};
use crate::client::intrinsic::vulnerability::{
    Vulnerability, VulnerabilityInputSpec, VulnerabilitySpec,
};
use crate::client::intrinsic::IntrinsicGuacClient;
use crate::client::{Error, Id};
use serde::{Deserialize, Serialize};

mod ingest;
mod query;

//#[derive(Debug, Serialize, Deserialize)]
type Time = chrono::DateTime<Utc>;

impl IntrinsicGuacClient {
    pub async fn ingest_certify_vuln(
        &self,
        package: &PkgInputSpec,
        vulnerability: &VulnerabilityInputSpec,
        meta: &ScanMetadataInput,
    ) -> Result<Id, Error> {
        use self::ingest::ingest_certify_vuln;

        let variables = ingest_certify_vuln::Variables {
            package: package.into(),
            vulnerability: vulnerability.into(),
            meta: meta.into(),
        };

        let response_body =
            post_graphql::<IngestCertifyVuln, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        Ok(data.ingest_certify_vuln.id)
    }

    pub async fn certify_vuln(
        &self,
        certify_vuln_spec: &CertifyVulnSpec,
    ) -> Result<Vec<CertifyVuln>, Error> {
        use self::query::query_certify_vuln;

        let variables = query_certify_vuln::Variables {
            certify_vuln_spec: certify_vuln_spec.into(),
        };

        let response_body =
            post_graphql::<QueryCertifyVuln, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let mut certified = Vec::new();

        for entry in &data.certify_vuln {
            certified.push(entry.into());
        }

        Ok(certified)
    }
}

#[derive(Debug, Clone)]
pub struct CertifyVuln {
    pub id: String,
    pub package: Package,
    pub vulnerability: Vulnerability,
    pub metadata: ScanMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub db_uri: String,
    pub db_version: String,
    pub scanner_uri: String,
    pub scanner_version: String,
    pub time_scanned: Time,
    pub origin: String,
    pub collector: String,
}

pub type ScanMetadataInput = ScanMetadata;

#[derive(Debug, Clone, Default)]
pub struct CertifyVulnSpec {
    pub id: Option<String>,
    pub package: Option<PkgSpec>,
    pub vulnerability: Option<VulnerabilitySpec>,
    pub time_scanned: Option<Time>,
    pub db_uri: Option<String>,
    pub db_version: Option<String>,
    pub scanner_uri: Option<String>,
    pub scanner_version: Option<String>,
    pub origin: Option<String>,
    pub collector: Option<String>,
}
