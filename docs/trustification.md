In order to use `guac-rs` library with [trustification](http://trustification.io), start

* Run core trustification services

```
$ [trustification/deploy/compose]  docker-compose -f compose.yaml -f compose-guac.yaml up --force-recreate
```

* You can run the rest of the services manually

```
$ [trustification] RUST_LOG=info cargo run -p trust -- vexination api --devmode &
RUST_LOG=info cargo run -p trust -- bombastic api --devmode &
RUST_LOG=info cargo run -p trust -- v11y api --devmode &
RUST_LOG=info cargo run -p trust -- vexination indexer --devmode &
RUST_LOG=info cargo run -p trust -- bombastic indexer --devmode &
RUST_LOG=info cargo run -p trust -- v11y indexer --devmode &
```

* You might want to run SPoG API separately as that's the service that uses `guac-rs` library the most

```
RUST_LOG=info cargo run -p trust -- spog api --devmode
```

* Ingest SBOM data from the ds1 set

```
$ [trustification] RUST_LOG=info cargo run -p trust bombastic walker --sink http://localhost:8082 --devmode --source ./data/ds1/sbom
```

* After SBOMs have been ingested, ingest the VEX files

```
$ [trustification] RUST_LOG=info cargo run -p trust -- vexination walker --devmode -3 --sink http://localhost:8081/api/v1/vex --source ./data/ds1/csaf
```

* Run v11y walker

```
RUST_LOG=info cargo run -p trust -- v11y walker --devmode --source ../cvelistV5/
```

* After this Trustification and Guac should be properly configured and populated with the test dataset
* You can access [Guac GraphQL explorer](http://localhost:8085)
* Some example generic queries to run can be found [here](https://github.com/guacsec/guac/tree/main/pkg/assembler/graphql/examples)
* Examples of trustification specific queries can be found [here](../example/queries/)
* You can also access the database directly with 
```
psql -h localhost -U guac guac
```
and explore the data
* [Examples](../lib/tests/spog.rs) are set to run against the instance of Guac started in the trustification context. These contain a good example of how to use some of these queries.

TODO: They don't work with ds1 dataset and are more examples than tests. If un-ignored, they can be ran as

```
cargo test product_by_cve -- --nocapture
```

* SPoG API uses guac-rs to make queries to the Guac. It also contains a few examples currently described as [tests](https://github.com/trustification/trustification/blob/main/spog/api/src/service/guac.rs), which can be ran against running Guac instance


* SPoG API can be also tested directly, like for example

```
$ TOKEN=$(curl -s -d "client_id=walker" -d "client_secret=ZVzq9AMOVUdMY1lSohpx1jI3aW56QDPS" -d 'grant_type=client_credentials' \
  'http://localhost:8090/realms/chicken/protocol/openid-connect/token' | jq -r .access_token)
$ curl -v -X GET --oauth2-bearer $TOKEN "http://localhost:8083/api/v1/cve/cve-2023-34454/related-products" | jq
```
