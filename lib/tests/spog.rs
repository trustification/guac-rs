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

//TODO do proper testing
// ./bin/guacone collect files --gql-addr http://localhost:8085/query ./rhel-7.9.z.json
// ./bin/guacone collect files --gql-addr http://localhost:8085/query ./cve-2022-2284.json
#[ignore]
#[tokio::test]
async fn find_vulnerability() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&"http://localhost:8085/query");

    let result = client
        .semantic()
        .find_vulnerability("pkg:guac/pkg/rhel-7.9.z@7.9.z", Some(0), Some(20))
        .await?;
    println!("result {:?}", result);

    Ok(())
}

//TODO do proper testing
// ./bin/guacone collect files --gql-addr http://localhost:8085/query ./rhel-7.9.z.json
// ./bin/guacone collect files --gql-addr http://localhost:8085/query ./cve-2022-2284.json
#[ignore]
#[tokio::test]
async fn find_vulnerability_by_sbom_uri() -> Result<(), anyhow::Error> {
    let client = GuacClient::new(&"http://localhost:8085/query");

    let result = client
        .semantic()
        .find_vulnerability_by_sbom_uri("https://access.redhat.com/security/data/sbom/beta/spdx/rhel-7.9.z-c98403ce-5e02-4278-98ec-b36ecd1f46a5", Some(0), Some(20))
        .await?;
    println!("{}", serde_json::to_string_pretty(&result).unwrap());

    Ok(())
}
