# Guac Rust library


## Use

### Run Guac server

```
docker run -p 8080:8080 ghcr.io/dejanb/local-organic-guac bash -c "/opt/guac/guacone gql-server --gql-debug"
```

### Ingest data

```
docker run -v $(pwd)/example:/example --network=host ghcr.io/dejanb/local-organic-guac bash -c "/opt/guac/guacone files /example/seedwing-java-example.bom"
```

## Contribute
### Run Guac server

```
git clone git@github.com:guacsec/guac.git
git clone git@github.com:dejanb/guac-rs.git
cd guac
make build
go run cmd/graphql_playground/main.go --neo4j=false --memory
```

### Ingest data

```
bin/guacone files ../guac-rs/examples/bom.json
```


### Update schema

```
cargo install graphql_client_cli --force
graphql-client introspect-schema http://localhost:8080/query > schema.json
```
