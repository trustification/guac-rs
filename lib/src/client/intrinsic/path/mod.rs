use crate::client::graph::{Edge, Node};
use crate::client::intrinsic::path::neighbors::Neighbors;
use crate::client::intrinsic::IntrinsicGuacClient;
use crate::client::{Error, Id};
use chrono::Utc;
use graphql_client::reqwest::post_graphql;

mod neighbors;
mod node;

impl IntrinsicGuacClient {
    pub async fn neighbors(&self, node: &Id, using_only: Vec<Edge>) -> Result<Vec<Node>, Error> {
        use self::neighbors::neighbors;

        let variables = neighbors::Variables {
            node: node.clone(),
            using_only: using_only.iter().map(|e| e.into()).collect(),
        };

        let response_body = post_graphql::<Neighbors, _>(self.client(), self.url(), variables).await?;

        if let Some(errors) = response_body.errors {
            return Err(Error::GraphQL(errors));
        }

        let data = response_body.data.ok_or(Error::GraphQL(vec![]))?;

        Ok(data.neighbors.iter().map(|e| e.into()).collect())
    }
}
