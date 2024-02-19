use chrono::Utc;
use graphql_client::reqwest::post_graphql;
use packageurl::PackageUrl;
use serde::{Deserialize, Serialize};

use crate::client::intrinsic::certify_good::ingest::IngestCertifyGood;
use crate::client::intrinsic::certify_good::query::QueryCertifyGood;
use crate::client::intrinsic::{
    IntrinsicGuacClient, MatchFlags, PackageSourceOrArtifact, PackageSourceOrArtifactInput, PackageSourceOrArtifactSpec,
};
use crate::client::{Error, Id};

mod ingest;
mod query;

type Time = chrono::DateTime<Utc>;

impl IntrinsicGuacClient {
    pub async fn ingest_certify_good<MF: Into<MatchFlags>>(
        &self,
        subject: &PackageSourceOrArtifactInput,
        pkg_match_type: MF,
        certify_good: &CertifyGoodInputSpec,
    ) -> Result<Id, Error> {
        use self::ingest::ingest_certify_good;

        let variables = ingest_certify_good::Variables {
            subject: subject.into(),
            pkg_match_type: pkg_match_type.into().into(),
            certify_good: certify_good.into(),
        };

        let response_body = post_graphql::<IngestCertifyGood, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        Ok(data.ingest_certify_good)
    }

    pub async fn certify_good(&self, certify_good_spec: &CertifyGoodSpec) -> Result<Vec<CertifyGood>, Error> {
        use self::query::query_certify_good;

        let variables = query_certify_good::Variables {
            certify_good_spec: certify_good_spec.into(),
        };
        let response_body = post_graphql::<QueryCertifyGood, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        let mut certified = Vec::new();

        for entry in &data.certify_good {
            certified.push(entry.into());
        }

        Ok(certified)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertifyGood {
    pub id: Id,
    pub subject: PackageSourceOrArtifact,
    pub justification: String,
    pub origin: String,
    pub collector: String,
    pub known_since: Option<Time>,
}

#[derive(Default, Debug, Clone)]
pub struct CertifyGoodSpec {
    pub id: Option<Id>,
    pub subject: Option<PackageSourceOrArtifactSpec>,
    pub justification: Option<String>,
    pub origin: Option<String>,
    pub collector: Option<String>,
    pub known_since: Option<Time>,
}

impl From<&PackageUrl<'_>> for CertifyGoodSpec {
    fn from(purl: &PackageUrl) -> Self {
        Self {
            subject: Some(PackageSourceOrArtifactSpec {
                package: Some(purl.clone().into()),
            }),
            ..Default::default()
        }
    }
}

pub struct CertifyGoodInputSpec {
    pub justification: String,
    pub origin: String,
    pub collector: String,
    pub known_since: Time,
}
