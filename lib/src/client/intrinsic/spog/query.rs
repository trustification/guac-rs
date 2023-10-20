use crate::client::graph::Node;
use chrono::Utc;
use graphql_client::GraphQLQuery;

type Time = chrono::DateTime<Utc>;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/client/intrinsic/schema.json",
    query_path = "src/client/intrinsic/spog/spog.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct QuerySpog;
