use crate::client::certify_bad::ingest::IngestCertifyBad;
use crate::client::certify_bad::query::{CertifyBad, QueryCertifyBad};
use crate::client::GuacClient;
use anyhow::Context;
use graphql_client::reqwest::post_graphql;

pub mod ingest;
pub mod query;

impl GuacClient {
    pub async fn certify_bad(&self, purl: &str) -> Result<Vec<CertifyBad>, anyhow::Error> {
        use self::query::query_certify_bad;

        let pkg = query_certify_bad::PkgSpec::try_from(purl)?;
        let variables = query_certify_bad::Variables { package: Some(pkg) };
        let response_body =
            post_graphql::<QueryCertifyBad, _>(&self.client, self.url.to_owned(), variables)
                .await?;
        let response_data = response_body
            .data
            .with_context(|| "No data found in response");

        let mut certified = Vec::new();

        for entry in response_data?.certify_bad {
            certified.push(CertifyBad {
                justification: entry.justification,
                origin: entry.origin,
                collector: entry.collector,
            });
        }

        Ok(certified)
    }

    pub async fn ingest_certify_bad(
        &self,
        purl: &str,
        origin: String,
        collector: String,
        justification: String,
    ) -> Result<(), anyhow::Error> {
        use self::ingest::ingest_certify_bad;

        let pkg = ingest_certify_bad::PkgInputSpec::try_from(purl)?;
        let variables = ingest_certify_bad::Variables {
            package: pkg,
            justification,
            collector,
            origin,
        };
        let response_body =
            post_graphql::<IngestCertifyBad, _>(&self.client, self.url.to_owned(), variables)
                .await?;

        println!("{:?}", response_body);

        let _ = response_body
            .data
            .with_context(|| "No data found in response")?;

        Ok(())
    }
}
