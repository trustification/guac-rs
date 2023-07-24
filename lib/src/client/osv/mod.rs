use crate::client::certify_vuln::Osv;
use crate::client::osv::ingest::IngestOsv;
use crate::client::GuacClient;
use anyhow::Context;
use graphql_client::reqwest::post_graphql;

pub mod ingest;
pub mod query;

impl GuacClient {
    pub async fn ingest_osv(&self, osv: Osv) -> Result<(), anyhow::Error> {
        use self::ingest::ingest_osv;

        let variables = ingest_osv::Variables {
            osv: osv.try_into()?,
        };

        let response_body =
            post_graphql::<IngestOsv, _>(&self.client, self.url.to_owned(), variables).await?;

        println!("{:?}", response_body);

        let _ = response_body
            .data
            .with_context(|| "No data found in response")?;

        Ok(())
    }
}
