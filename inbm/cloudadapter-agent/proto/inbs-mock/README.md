# inbs-mock

This serves as a mock INBS that can be used to send ping requests to cloudadapter. The main loop will ping cloudadapter once per second.

## Prerequisites

- Go 1.22 or higher
- Protobuf tools installed for regenerating protobuf golang code

## Getting Started

The server can be started in two modes: secure and insecure. By default, the server runs in insecure mode.

### Insecure Mode

To run the server in insecure mode, simply start the server without any additional flags:

```bash
go run inbs-mock.go
```

This will start the server on TCP port 5002, handling incoming gRPC requests without TLS encryption.

### Secure Mode

To run the server in secure mode, you will need a TLS certificate and corresponding private key. Start the server with the `secure` flag and specify the paths to your TLS files using `cert` and `key`:

```bash
go run inbs-mock.go -secure -cert=path/to/your/certfile.crt -key=path/to/your/keyfile.key
```

Ensure that the certificate and key files exist at the specified paths and are valid. This configuration starts the server with TLS encryption, enhancing the communication security between the client and the server.

#### Generating TLS Certificates

If you need to generate a new self-signed certificate and key for testing purposes, you can use the following `openssl` command:

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
```

This command creates a new 4096-bit RSA key and a corresponding self-signed certificate valid for 365 days with "localhost" as the common name (CN).

Be sure to replace `"path/to/your/certfile.crt"` and `"path/to/your/keyfile.key"` in the server start command with the actual paths where your `server.crt` and `server.key` are stored.

## Additional Information

The server utilizes gRPC interceptors for basic authentication. For testing purposes, ensure that the client sends the correct metadata with a "token" key having the value "good_token".
