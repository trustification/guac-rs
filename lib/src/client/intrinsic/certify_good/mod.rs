use anyhow::Context;
use graphql_client::reqwest::post_graphql;

use crate::client::intrinsic::certify_good::ingest::IngestCertifyGood;
use crate::client::intrinsic::certify_good::query::QueryCertifyGood;
use crate::client::{Error, GuacClient};
use serde::Serialize;
use crate::client::intrinsic::{Id, IntrinsicGuacClient, MatchFlags, PackageSourceOrArtifact, PackageSourceOrArtifactInput, PackageSourceOrArtifactSpec};

pub mod ingest;
pub mod query;

impl IntrinsicGuacClient<'_> {

    pub async fn ingest_certify_good(
        &self,
        subject: &PackageSourceOrArtifactInput,
        pkg_match_type: &MatchFlags,
        certify_good: &CertifyGoodInputSpec,
    ) -> Result<Id, Error> {
        use self::ingest::ingest_certify_good;

        let variables = ingest_certify_good::Variables {
            subject: subject.into(),
            pkg_match_type: pkg_match_type.into(),
            certify_good: certify_good.into(),
        };

        let response_body =
            post_graphql::<IngestCertifyGood, _>(self.client(), self.url(), variables)
                .await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors))
        }

        let data = response_body
            .data
            .ok_or( Error::GraphQL(vec![]))?;

        Ok( data.ingest_certify_good.id )
    }

    pub async fn certify_good(&self, certify_good_spec: &CertifyGoodSpec) -> Result<Vec<CertifyGood>, Error> {
        use self::query::query_certify_good;

        let variables = query_certify_good::Variables {
            certify_good_spec: certify_good_spec.into(),
        };
        let response_body =
            post_graphql::<QueryCertifyGood, _>(self.client(), self.url(), variables)
                .await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors))
        }

        let data = response_body
            .data
            .ok_or( Error::GraphQL(vec![]))?;

        let mut certified = Vec::new();

        for entry in &data.certify_good {
            certified.push(entry.into() );
        }

        Ok(certified)
    }
}

pub struct CertifyGood {
    id: Id,
    subject: PackageSourceOrArtifact,
    justification: String,
    origin: String,
    collector: String,
}

pub struct CertifyGoodSpec {
    id: Option<Id>,
    subject: Option<PackageSourceOrArtifactSpec>,
    justification: Option<String>,
    origin: Option<String>,
    collector: Option<String>,
}

pub struct CertifyGoodInputSpec {
    justification: String,
    origin: String,
    collector: String,
}
