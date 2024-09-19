use crate::client::intrinsic::vuln_equal::ingest::{ingest_vuln_equal, IngestVulnEqual};
use crate::client::intrinsic::vuln_equal::query::QueryVulnEqual;
use crate::client::intrinsic::vulnerability::{
    IDorVulnerabilityInput, Vulnerability, VulnerabilityInputSpec, VulnerabilitySpec,
};
use crate::client::intrinsic::IntrinsicGuacClient;
use crate::client::{Error, Id};
use graphql_client::reqwest::post_graphql;

mod ingest;
mod query;

impl IntrinsicGuacClient {
    pub async fn ingest_vuln_equal(
        &self,
        vulnerability: &IDorVulnerabilityInput,
        other_vulnerability: &IDorVulnerabilityInput,
        vuln_equal: &VulnEqualInputSpec,
    ) -> Result<Id, Error> {
        use self::ingest::ingest_vuln_equal;

        let variables = ingest_vuln_equal::Variables {
            vulnerability: vulnerability.into(),
            other_vulnerability: other_vulnerability.into(),
            vuln_equal: vuln_equal.into(),
        };

        let response_body = post_graphql::<IngestVulnEqual, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        Ok(data.ingest_vuln_equal)
    }

    pub async fn vuln_equal(&self, vuln_equal_spec: &VulnEqualSpec) -> Result<Vec<VulnEqual>, Error> {
        use self::query::query_vuln_equal;

        let variables = query_vuln_equal::Variables {
            vuln_equal_spec: vuln_equal_spec.into(),
        };

        let response_body = post_graphql::<QueryVulnEqual, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let mut equal = Vec::new();

        for entry in &data.vuln_equal {
            equal.push(entry.into());
        }

        Ok(equal)
    }
}

#[derive(Debug, Clone)]
pub struct VulnEqual {
    pub id: Id,
    pub vulnerabilities: Vec<Vulnerability>,
    pub justification: String,
    pub origin: String,
    pub collector: String,
}

#[derive(Debug, Clone, Default)]
pub struct VulnEqualSpec {
    pub id: Option<Id>,
    pub vulnerabilities: Option<Vec<VulnerabilitySpec>>,
    pub justification: Option<String>,
    pub origin: Option<String>,
    pub collector: Option<String>,
    pub document_ref: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VulnEqualInputSpec {
    pub justification: String,
    pub origin: String,
    pub collector: String,
    pub document_ref: String,
}
