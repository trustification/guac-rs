mod common;

use guac::client::GuacClient;

//TODO do proper testing
// ./bin/guacone collect files --gql-addr http://localhost:8085/query ./rhel-7.9.z.json
// ./bin/guacone collect files --gql-addr http://localhost:8085/query ./cve-2022-2284.json
#[ignore]
#[tokio::test]
async fn product_by_cve() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&"http://localhost:8085/query");

    let result = client.semantic().product_by_cve("cve-2022-2284").await?;
    println!("result {:?}", result);

    Ok(())
}
