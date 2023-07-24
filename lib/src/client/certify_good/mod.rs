use anyhow::Context;
use graphql_client::reqwest::post_graphql;

use crate::client::certify_good::ingest::IngestCertifyGood;
use crate::client::certify_good::query::QueryCertifyGood;
use crate::client::GuacClient;
use serde::Serialize;

pub mod ingest;
pub mod query;

#[derive(Serialize)]
pub struct CertifyGood {
    pub justification: String,
    pub origin: String,
    pub collector: String,
}

impl GuacClient {
    pub async fn certify_good(&self, purl: &str) -> Result<Vec<CertifyGood>, anyhow::Error> {
        use self::query::query_certify_good;

        let pkg = query_certify_good::PkgSpec::try_from(purl)?;
        let variables = query_certify_good::Variables { package: Some(pkg) };
        let response_body =
            post_graphql::<QueryCertifyGood, _>(&self.client, self.url.to_owned(), variables)
                .await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");

        let mut certified = Vec::new();

        for entry in response_data?.certify_good {
            certified.push(CertifyGood {
                justification: entry.justification,
                origin: entry.origin,
                collector: entry.collector,
            });
        }

        Ok(certified)
    }

    pub async fn ingest_certify_good(
        &self,
        purl: &str,
        origin: String,
        collector: String,
        justification: String,
    ) -> Result<(), anyhow::Error> {
        use self::ingest::ingest_certify_good;
        let pkg = ingest_certify_good::PkgInputSpec::try_from(purl)?;
        let variables = ingest_certify_good::Variables {
            package: pkg,
            justification,
            collector,
            origin,
        };
        let response_body =
            post_graphql::<IngestCertifyGood, _>(&self.client, self.url.to_owned(), variables)
                .await?;

        let _ = response_body
            .data
            .with_context(|| "No data found in response")?;

        Ok(())
    }
}
