use graphql_client::GraphQLQuery;

use crate::client::graph::Node;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/spog/spog.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QuerySpog;
