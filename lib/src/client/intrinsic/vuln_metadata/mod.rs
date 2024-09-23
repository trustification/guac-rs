use chrono::Utc;
use graphql_client::reqwest::post_graphql;

use crate::client::intrinsic::vuln_metadata::ingest::IngestVulnerabilityMetadata;
use crate::client::intrinsic::vuln_metadata::query::{query_vulnerability_metadata, QueryVulnerabilityMetadata};
use crate::client::intrinsic::vulnerability::{IDorVulnerabilityInput, VulnerabilityInputSpec, VulnerabilitySpec};
use crate::client::intrinsic::IntrinsicGuacClient;
use crate::client::{Error, Id};

mod ingest;
mod query;

type Time = chrono::DateTime<Utc>;

impl IntrinsicGuacClient {
    pub async fn ingest_vuln_metadata(
        &self,
        vulnerability: &IDorVulnerabilityInput,
        vulnerability_metadata: &VulnerabilityMetadataInputSpec,
    ) -> Result<Id, Error> {
        use self::ingest::ingest_vulnerability_metadata;

        let variables = ingest_vulnerability_metadata::Variables {
            vulnerability: vulnerability.into(),
            vulnerability_metadata: vulnerability_metadata.into(),
        };

        let response_body =
            post_graphql::<IngestVulnerabilityMetadata, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        Ok(data.ingest_vulnerability_metadata)
    }

    pub async fn vuln_metadata(
        &self,
        vulnerability_metadata_spec: &VulnerabilityMetadataSpec,
    ) -> Result<Vec<VulnerabilityMetadata>, Error> {
        use self::query::query_vulnerability_metadata;

        let variables = query_vulnerability_metadata::Variables {
            vulnerability_metadata_spec: vulnerability_metadata_spec.into(),
        };

        let response_body = post_graphql::<QueryVulnerabilityMetadata, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let mut meta = Vec::new();

        for entry in &data.vulnerability_metadata {
            meta.push(entry.into());
        }

        Ok(meta)
    }
}

#[derive(Debug, Clone)]
pub struct VulnerabilityMetadata {
    pub id: Id,
    pub score_type: VulnerabilityScoreType,
    pub score_value: f64,
    pub timestamp: Time,
    pub origin: String,
    pub collector: String,
}

#[derive(Debug, Clone)]
pub struct VulnerabilityMetadataInputSpec {
    pub score_type: VulnerabilityScoreType,
    pub score_value: f64,
    pub timestamp: Time,
    pub origin: String,
    pub collector: String,
    pub document_ref: String,
}

#[derive(Default, Debug, Clone)]
pub struct VulnerabilityMetadataSpec {
    pub id: Option<Id>,
    pub vulnerability: Option<VulnerabilitySpec>,
    pub score_type: Option<VulnerabilityScoreType>,
    pub score_value: Option<f64>,
    pub comparator: Option<Comparator>,
    pub timestamp: Option<Time>,
    pub origin: Option<String>,
    pub collector: Option<String>,
    pub document_ref: Option<String>,
}

#[derive(Debug, Clone)]
pub enum VulnerabilityScoreType {
    CVSSv2,
    CVSSv3,
    CVSSv31,
    CVSSv4,
    EPSSv1,
    EPSSv2,
    OWASP,
    SSVC,
    Other(String),
}

#[derive(Debug, Clone)]
pub enum Comparator {
    Greater,
    Equal,
    Less,
    GreaterEqual,
    LessEqual,
}
