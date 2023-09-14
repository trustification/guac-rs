use guac::client::GuacClient;

use crate::common::guac_url;

mod common;

#[tokio::test]
async fn basic_client() {
    let client = GuacClient::new(&guac_url());

    client.intrinsic();
    client.semantic();

    client.intrinsic().semantic().intrinsic();
    client.semantic().intrinsic().semantic();
}
