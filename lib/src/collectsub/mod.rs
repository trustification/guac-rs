use std::time::SystemTime;

use serde::Serialize;
use tonic::transport::Channel;

use grpc::colect_subscriber_service_client::ColectSubscriberServiceClient;
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
    client: ColectSubscriberServiceClient<Channel>,
}

impl CollectSubClient {
    pub async fn new(url: String) -> anyhow::Result<Self> {
        Ok(Self {
            client: grpc::colect_subscriber_service_client::ColectSubscriberServiceClient::connect(
                url,
            )
            .await?,
        })
    }

    pub async fn get(
        &mut self,
        filters: Vec<Filter>,
        since: SystemTime,
    ) -> anyhow::Result<Vec<Entry>> {
        let filters = filters.iter().map(|e| e.into()).collect();

        let since = (since
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("time flies like an arrow")
            .as_secs()) as i64;

        let request = grpc::GetCollectEntriesRequest {
            filters,
            since_time: since,
        };

        let results = if let Ok(response) = self.client.get_collect_entries(request).await {
            response
                .get_ref()
                .entries
                .iter()
                .map(|e| e.into())
                .collect()
        } else {
            vec![]
        };

        Ok(results)
    }
}
