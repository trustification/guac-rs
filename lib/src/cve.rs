use graphql_client::GraphQLQuery;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/schema.json",
    query_path = "src/query/certify_vuln.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct CertifyVulnQ2;
