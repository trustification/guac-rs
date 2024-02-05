pub mod graph;
pub mod intrinsic;
pub mod semantic;

use crate::client::intrinsic::IntrinsicGuacClient;
use crate::client::semantic::SemanticGuacClient;
use std::sync::atomic::AtomicU64;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Purl parsing error: {0}")]
    Purl(#[from] packageurl::Error),
    #[error("Http request error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("GraphQL response error: {}", format_graphql_message(.0))]
    GraphQL(Vec<graphql_client::Error>),
}

fn format_graphql_message(inner: &Vec<graphql_client::Error>) -> String {
    if inner.is_empty() {
        "<unspecified>".to_string()
    } else {
        format!("{:#?}", inner)
    }
}

#[derive(Clone)]
pub struct GuacClient {
    pub(crate) client: reqwest::Client,
    pub(crate) url: String,
}

impl GuacClient {
    pub fn new(url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.to_owned(),
        }
    }

    pub fn with_client(url: String, client: reqwest::Client) -> Self {
        Self { client, url }
    }

    pub fn semantic(&self) -> SemanticGuacClient {
        SemanticGuacClient::new(self)
    }

    pub fn intrinsic(&self) -> IntrinsicGuacClient {
        IntrinsicGuacClient::new(self)
    }
}

static VERSION: AtomicU64 = AtomicU64::new(1);

pub type Id = String;
