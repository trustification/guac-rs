use std::path::Path;
use std::time::SystemTime;

use serde::Serialize;
use tonic::codegen::tokio_stream::StreamExt;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};

use grpc::collect_subscriber_service_client::CollectSubscriberServiceClient;
use grpc::CollectDataType;
use grpc::CollectEntryFilter;

#[allow(clippy::enum_variant_names)]
mod grpc {
    tonic::include_proto!("guacsec.guac.collect_subscriber.schema");
}

pub enum Filter {
    Unknown(String),
    Git(String),
    Oci(String),
    Purl(String),
    GithubRelease(String),
}

impl From<&Filter> for CollectEntryFilter {
    fn from(value: &Filter) -> Self {
        match value {
            Filter::Unknown(glob) => CollectEntryFilter {
                r#type: CollectDataType::DatatypeUnknown as i32,
                glob: glob.to_owned(),
            },
            Filter::Git(glob) => CollectEntryFilter {
                r#type: CollectDataType::DatatypeGit as i32,
                glob: glob.to_owned(),
            },
            Filter::Oci(glob) => CollectEntryFilter {
                r#type: CollectDataType::DatatypeOci as i32,
                glob: glob.to_owned(),
            },
            Filter::Purl(glob) => CollectEntryFilter {
                r#type: CollectDataType::DatatypePurl as i32,
                glob: glob.to_owned(),
            },
            Filter::GithubRelease(glob) => CollectEntryFilter {
                r#type: CollectDataType::DatatypeGithubRelease as i32,
                glob: glob.to_owned(),
            },
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Entry {
    Unknown(String),
    Git(String),
    Oci(String),
    Purl(String),
    GithubRelease(String),
}

impl From<&grpc::CollectEntry> for Entry {
    fn from(entry: &grpc::CollectEntry) -> Self {
        match entry.r#type {
            0 => Entry::Unknown(entry.value.to_owned()),
            1 => Entry::Git(entry.value.to_owned()),
            2 => Entry::Oci(entry.value.to_owned()),
            3 => Entry::Purl(entry.value.to_owned()),
            4 => Entry::GithubRelease(entry.value.to_owned()),
            _ => Entry::Unknown(entry.value.to_owned()),
        }
    }
}

pub struct CollectSubClient {
    client: CollectSubscriberServiceClient<Channel>,
}

impl CollectSubClient {
    pub async fn new(url: String) -> anyhow::Result<Self> {
        Ok(Self {
            client: grpc::collect_subscriber_service_client::CollectSubscriberServiceClient::connect(url).await?,
        })
    }

    pub async fn new_with_ca_certificate(url: String, ca_certificate_pem_path: String) -> anyhow::Result<Self> {
        let cert = std::fs::read_to_string(ca_certificate_pem_path)?;
        Ok(Self {
            client: grpc::collect_subscriber_service_client::CollectSubscriberServiceClient::connect(
                tonic::transport::Endpoint::new(url)?
                    .tls_config(ClientTlsConfig::new().ca_certificate(Certificate::from_pem(cert)))?,
            )
            .await?,
        })
    }

    pub async fn get(&mut self, filters: Vec<Filter>, since: SystemTime) -> anyhow::Result<Vec<Entry>> {
        let filters = filters.iter().map(|e| e.into()).collect();

        let since = (since
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time flies like an arrow")
            .as_secs()) as i64;

        let request = grpc::GetCollectEntriesRequest {
            filters,
            since_time: since,
        };

        let mut results = vec![];
        // Make the streaming request to the server
        let get_collect_entries_result = self.client.get_collect_entries(request).await;
        match get_collect_entries_result {
            Ok(response) => {
                let mut stream = response.into_inner();
                // Process the stream of responses from the server
                while let Some(stream_response) = stream.next().await {
                    match stream_response {
                        Ok(entries) => results.append(
                            entries
                                .entries
                                .iter()
                                .map(|e| e.into())
                                .collect::<Vec<Entry>>()
                                .as_mut(),
                        ),
                        Err(e) => println!("Error while streaming: {}", e),
                    }
                }
            }
            Err(e) => println!("Error while collecting entries: {}", e),
        }

        Ok(results)
    }
}
