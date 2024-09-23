use chrono::Utc;
use graphql_client::reqwest::post_graphql;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};

use crate::client::intrinsic::certify_bad::ingest::IngestCertifyBad;
use crate::client::intrinsic::certify_bad::query::QueryCertifyBad;
use crate::client::intrinsic::{
    IntrinsicGuacClient, MatchFlags, PackageSourceOrArtifact, PackageSourceOrArtifactInput, PackageSourceOrArtifactSpec,
};
use crate::client::{Error, Id};

mod ingest;
mod query;

type Time = chrono::DateTime<Utc>;

impl IntrinsicGuacClient {
    pub async fn ingest_certify_bad<MF: Into<MatchFlags>>(
        &self,
        subject: &PackageSourceOrArtifactInput,
        pkg_match_type: MF,
        certify_bad: &CertifyBadInputSpec,
    ) -> Result<Id, Error> {
        use self::ingest::ingest_certify_bad;

        let variables = ingest_certify_bad::Variables {
            subject: subject.into(),
            pkg_match_type: pkg_match_type.into().into(),
            certify_bad: certify_bad.into(),
        };

        let response_body = post_graphql::<IngestCertifyBad, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        Ok(data.ingest_certify_bad)
    }

    pub async fn certify_bad(&self, certify_bad_spec: &CertifyBadSpec) -> Result<Vec<CertifyBad>, Error> {
        use self::query::query_certify_bad;

        let variables = query_certify_bad::Variables {
            certify_bad_spec: certify_bad_spec.into(),
        };
        let response_body = post_graphql::<QueryCertifyBad, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let mut certified = Vec::new();

        for entry in &data.certify_bad {
            certified.push(entry.into());
        }

        Ok(certified)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertifyBad {
    pub id: Id,
    pub subject: PackageSourceOrArtifact,
    pub justification: String,
    pub origin: String,
    pub collector: String,
    pub known_since: Option<Time>,
}

#[derive(Default, Debug, Clone)]
pub struct CertifyBadSpec {
    pub id: Option<Id>,
    pub subject: Option<PackageSourceOrArtifactSpec>,
    pub justification: Option<String>,
    pub origin: Option<String>,
    pub collector: Option<String>,
    pub known_since: Option<Time>,
    pub document_ref: Option<String>,
}

impl From<&PackageUrl<'_>> for CertifyBadSpec {
    fn from(purl: &PackageUrl) -> Self {
        Self {
            subject: Some(PackageSourceOrArtifactSpec {
                package: Some(purl.clone().into()),
            }),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertifyBadInputSpec {
    pub justification: String,
    pub origin: String,
    pub collector: String,
    pub known_since: Time,
    pub document_ref: String,
}
