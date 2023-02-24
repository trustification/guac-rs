use reqwest::blocking::Client;
use graphql_client::{reqwest::post_graphql_blocking as post_graphql, GraphQLQuery};
use anyhow::*;



#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "src/schema.json",
    query_path = "src/query/certify_vuln.gql",
    response_derives = "Debug, Serialize, Deserialize"
)]
pub struct Q4;


fn main() -> Result<(), anyhow::Error> {
    println!("Hello, world!");

    let variables = q4::Variables;

    let client = Client::new();

    let response_body =
        post_graphql::<Q4, _>(&client, "http://localhost:8080/query", variables).unwrap();

    let response_data = response_body.data.expect("missing response data");

    //println!("{}", serde_json::to_string_pretty(&response_body).unwrap());
    println!("{:?}", response_data);

    //let response_data: q4::ResponseData = response_body.data.expect("missing response data");

    Ok(())

}
