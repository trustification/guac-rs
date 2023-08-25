use guac::client::GuacClient;

use common::GUAC_URL;
mod common;

#[tokio::test]
async fn basic_client() {
    let client = GuacClient::new(GUAC_URL);

    client.intrinsic();
    client.semantic();

    client.intrinsic().semantic().intrinsic();
    client.semantic().intrinsic().semantic();
}
