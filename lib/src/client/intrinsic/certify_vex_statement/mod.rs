mod ingest;
mod query;

use super::vulnerability::Vulnerability;
use crate::client::intrinsic::certify_vex_statement::ingest::IngestCertifyVexStatement;
use crate::client::intrinsic::certify_vex_statement::query::{
    query_certify_vex_statement, QueryCertifyVexStatement,
};
use crate::client::intrinsic::vulnerability::{VulnerabilityInputSpec, VulnerabilitySpec};
use crate::client::intrinsic::{
    IntrinsicGuacClient, PackageOrArtifact, PackageOrArtifactInput, PackageOrArtifactSpec,
};
use crate::client::{Error, Id};
use chrono::Utc;
use graphql_client::reqwest::post_graphql;

type Time = chrono::DateTime<Utc>;

impl IntrinsicGuacClient {
    pub async fn ingest_certify_vex_statement(
        &self,
        subject: &PackageOrArtifactInput,
        vulnerability: &VulnerabilityInputSpec,
        vex_statement: &VexStatementInputSpec,
    ) -> Result<Id, Error> {
        use self::ingest::ingest_certify_vex_statement;

        let variables = ingest_certify_vex_statement::Variables {
            subject: subject.into(),
            vulnerability: vulnerability.into(),
            vex_statement: vex_statement.into(),
        };

        let response_body =
            post_graphql::<IngestCertifyVexStatement, _>(self.client(), self.url(), variables)
                .await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        Ok(data.ingest_vex_statement)
    }

    pub async fn certify_vex_statement(
        &self,
        certify_vex_statement_spec: &CertifyVexStatementSpec,
    ) -> Result<Vec<CertifyVexStatement>, Error> {
        use self::query::query_certify_vex_statement;

        let variables = query_certify_vex_statement::Variables {
            certify_vex_statement_spec: certify_vex_statement_spec.into(),
        };

        let response_body =
            post_graphql::<QueryCertifyVexStatement, _>(self.client(), self.url(), variables)
                .await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let mut certified = Vec::new();

        for entry in &data.certify_vex_statement {
            certified.push(entry.into());
        }

        Ok(certified)
    }
}

#[derive(Debug, Clone)]
pub struct CertifyVexStatement {
    pub id: Id,
    pub subject: PackageOrArtifact,
    pub vulnerability: Vulnerability,
    pub status: VexStatus,
    pub vex_justification: VexJustification,
    pub statement: String,
    pub status_notes: String,
    pub known_since: Time,
    pub origin: String,
    pub collector: String,
}

#[derive(Debug, Clone)]
pub enum VexStatus {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
    Other(String),
}

#[derive(Debug, Clone)]
pub enum VexJustification {
    ComponentNotPresent,
    VulnerableCodeNotPresent,
    VulnerableCodeNotInExecutePath,
    VulnerableCodeCannotBeControlledByAdversary,
    InlineMitigationsAlreadyExist,
    NotProvided,
    Other(String),
}

#[derive(Clone, Debug)]
pub struct VexStatementInputSpec {
    pub status: VexStatus,
    pub vex_justification: VexJustification,
    pub statement: String,
    pub status_notes: String,
    pub known_since: Time,
    pub origin: String,
    pub collector: String,
}

#[derive(Debug, Default)]
pub struct CertifyVexStatementSpec {
    pub id: Option<Id>,
    pub subject: Option<PackageOrArtifactSpec>,
    pub vulnerability: Option<VulnerabilitySpec>,
    pub status: Option<VexStatus>,
    pub vex_justification: Option<VexJustification>,
    pub statement: Option<String>,
    pub status_notes: Option<String>,
    pub known_since: Option<Time>,
    pub origin: Option<String>,
    pub collector: Option<String>,
}
