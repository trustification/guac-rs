# Guac Rust library

### Run Guac server

```
go run cmd/graphql_playground/main.go --neo4j=false --memory
```

### Update schema

```
cargo install graphql_client_cli --force
graphql-client introspect-schema http://localhost:8080/query > schema.json
```
