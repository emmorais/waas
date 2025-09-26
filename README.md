Wallet as a Service

# Testing

Running the server:

```
cargo run
```

If you open it on a browser, it will complain because the certificate is self-signed, which is fine for testing purposes. 

## Curl

```
 curl -k https://localhost:8443/index.html  
```
