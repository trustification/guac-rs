# Guac Rust library

### Run Guac server

```
BACKEND=testing TEST=true go run pkg/assembler/graphql/main/server.go
```

### Update schema

```
cargo install graphql_client_cli --force
graphql-client introspect-schema http://localhost:8080/query > schema.json
```
