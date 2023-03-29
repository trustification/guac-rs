# Guac Rust library


## Dev mode
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


## Update schema

```
cargo install graphql_client_cli --force
graphql-client introspect-schema http://localhost:8080/query > schema.json
```
