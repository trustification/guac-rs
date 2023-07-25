use self::ingest_osv::OSVInputSpec;
use crate::client::certify_vuln::Osv;
use graphql_client::GraphQLQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/schema.json",
    query_path = "src/client/osv/osv.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IngestOsv;

impl TryFrom<Osv> for OSVInputSpec {
    type Error = anyhow::Error;

    fn try_from(osv: Osv) -> Result<Self, Self::Error> {
        Ok(Self { osv_id: osv.osv_id })
    }
}

#[cfg(test)]
pub mod test {
    use crate::client::certify_vuln::{Metadata, Vulnerability};
    use crate::client::GuacClient;

    use super::*;

    #[tokio::test]
    async fn ingest_osv() -> Result<(), anyhow::Error> {
        let client = GuacClient::new("http://localhost:8080/query".into());

        client
            .ingest_package("pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0")
            .await?;

        let result = client
            .ingest_osv(Osv {
                osv_id: "osv-example-vuln".to_string(),
            })
            .await;

        assert!(result.is_ok());

        println!("{:?}", result);

        Ok(())
    }

    #[tokio::test]
    async fn ingest_vuln() -> Result<(), anyhow::Error> {
        let client = GuacClient::new("http://localhost:8080/query".into());

        client
            .ingest_osv(Osv {
                osv_id: "osv-example-vuln".to_string(),
            })
            .await?;

        let vuln = Vulnerability::Osv(Osv {
            osv_id: "osv-example-vuln".to_string(),
        });

        let meta = Metadata {
            db_uri: "http://db.example.com/".to_string(),
            db_version: "1.0".to_string(),
            scanner_uri: "collectorist-osv".to_string(),
            scanner_version: "1.0".to_string(),
            time_scanned: Default::default(),
            origin: "OSV".to_string(),
            collector: "collectorist-osv".to_string(),
        };

        client
            .ingest_package("pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0")
            .await?;

        client
            .ingest_certify_vuln(
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.13.0",
                vuln,
                meta,
            )
            .await?;

        Ok(())
    }
}
