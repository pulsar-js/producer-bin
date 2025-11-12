# @pulsar-js/producer (binaries)

This repository houses the pre-built binaries for the [@pulsar/producer](https://github.com/pulsar-js/producer) npm module.

Since this is a niche module, we are only building binaries for the platforms we know users are working with. If you want to use this on one of the operating systems/architectures listed above that isn't yet supported, open an issue and we'll add it.

## Supported OS/Architectures

**AIX**
- [ ] ppc64

**Android**
- [ ] amd64
- [ ] arm64

**FreeBSD**
- [ ] amd64
- [ ] arm64

**NetBSD**
- [ ] amd64
- [ ] arm64

**OpenBSD**
- [ ] amd64
- [ ] arm64

**Linux**
- [x] amd64
- [x] arm64
- [ ] 386
- [ ] loong64
- [ ] mips64le
- [x] ppc64le
- [ ] riscv64
- [x] s390x

**macOS** (Darwin)
- [x] amd64
- [x] arm64

**SunOS**
- [ ] amd64

**Windows**
- [x] amd64
- [x] arm64
- [x] 386

## Standalone Usage

```sh
Usage: pulsar-publish [<connection-string> [<message>]] [flags]

Publish messages to Apache Pulsar. v1.0.0

Arguments:
  [<connection-string>]    Server and topic to publish to. Example:
                           pulsar://localhost:5678/public/default/test
  [<message>]              Message to send.

Flags:
  -h, --help       Show context-sensitive help.
  -v, --version    Display the version.
  -V, --verbose    Enable verbose logging.

Message
      --key=STRING               Message key (for routing policy).
      --ordering-key=STRING      Message ordering key.
      --event-time=INT-64        Event time for the message (ms since epoch).
      --replication-cluster=REPLICATION-CLUSTER,...
                                 Replication cluster for the message (this can
                                 be specified multiple times).
      --disable-replication      Disable replication for the message.
      --sequence-id=INT-64       Sequence ID for the message.
      --deliver-after=INT-64     Delay delivery of the Shared or KeyShared
                                 subscription message by specified milliseconds.
      --deliver-at=INT-64        Deliver the Shared or KeyShared subscription
                                 message at the specified epoch timestamp in
                                 milliseconds.
  -p, --property=PROPERTY,...    Add a property to the message in key=value
                                 format. Can be specified multiple times.

OIDC Authentication
  --jwt=STRING              Path to JWT file or raw JWT string.
  --allow-unverified-jwt    Allow unverified JWT tokens.

mTLS Authentication
  --mtls-cert=STRING       Path to mTLS certificate file.
  --mtls-key=STRING        Path to mTLS key file.
  --mtls-ca-cert=STRING    Path to CA certificate file to verify the Pulsar TLS
                           certificate.

OAuth2 Authentication
  --oauth2-issuer=STRING         URL of the authentication provider which allows
                                 the Pulsar client to obtain an access token.
  --oauth2-private-key=STRING    Path to the private key file or raw content
                                 used to sign the access token request.
  --oauth2-audience=STRING       The OAuth 2.0 resource server identifier for
                                 the pulsar cluster. (ex: the broker URL)
  --oauth2-client-id=STRING      The OAuth 2.0 client identifier.

Basic Authentication
  --username=STRING    Username for basic authentication.
  --password=STRING    Password for basic authentication.

Athenz Authentication
  --athenz=STRING                URL for authentication.
  --athenz-proxy=STRING          Proxy URL for authentication.
  --athenz-provider-domain="pulsar"
                                 Provider Domain for authentication.
  --athenz-tenant=STRING         Tenant for authentication.
  --athenz-service=STRING        Service for authentication.
  --athenz-private-key=STRING    Path to private key file.
  --athenz-key-id=STRING         Private key ID.
  --athenz-cert-chain=STRING     Path to Athenz x509 certificate chain file.
                                 (required if using Copper Argos)
  --athenz-ca-cert=STRING        Path to Athenz CA certificate file. (required
                                 if using Copper Argos)

Producer
  --name="manual-producer"    Name of the producer.
  --timeout=30                Seconds before publish times out.
  --producer-property=PRODUCER-PROPERTY,...
                              Add a property to the producer in key=value
                              format. Can be specified multiple times.
  --test                      Test the connection without sending a message.
  ```