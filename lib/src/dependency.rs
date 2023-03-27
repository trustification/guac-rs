use graphql_client::GraphQLQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/schema.json",
    query_path = "src/query/is_dependency.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct GetDependencies;


#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/schema.json",
    query_path = "src/query/is_dependency.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct IsDependent;