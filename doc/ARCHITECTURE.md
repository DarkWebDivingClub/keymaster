# DWDC Key System Architecture

Status: Draft

This document defines the current architectural direction for KeyMaster,
Avatar, service avatars, and KeyVault.

## Goals

The system must:

- keep mnemonic phrases, derived private seeds, and private keys inside the
  KeyMaster and KeyVault security boundary;
- support protocol-specific operations without coupling KeyVault to external
  protocols;
- let a KeyMaster serve applications running on another host;
- support user authentication and approval before sensitive operations;
- expose native host interfaces such as SSH agent, GnuPG, and PKCS#11;
- allow transports and host adapters to evolve independently.

## Components

```text
Target host                                      Controller host or device

Application
    |
Native protocol
    |
Service avatar
    |
Uniform local Avatar API
    |
Avatar
    |
Authenticated Avatar-KeyMaster protocol
    |
KeyMaster
    |
Protocol service
    |
KeyVault
```

### KeyMaster

KeyMaster is the controller and security authority.

KeyMaster:

- owns identities, accounts, key metadata, configuration, and policy;
- records which protocol configurations and derived keys are active for each
  identity;
- implements protocol-specific services;
- determines which services and keys a caller may use;
- requests user authentication or explicit approval when policy requires it;
- manages sessions and delegated capabilities;
- translates protocol operations into constrained KeyVault calls;
- returns public information, signatures, decrypted data, or other operation
  results;
- records security-relevant audit information.

KeyMaster must not give Avatar unrestricted KeyVault access. In particular,
Avatar must not receive mnemonic phrases, BIP-39 passphrases, private seeds,
private keys, or an unrestricted key-derivation function.

Examples of KeyMaster services include:

- SSH service;
- OpenPGP service;
- Nostr service;
- TLS and X.509 service;
- Bitcoin service.

Each service defines its own versioned operations and data types. For example,
the SSH service may expose public-key lookup and SSH signing, while the Nostr
service may expose public-key lookup, event signing, and NIP-44
encryption/decryption.

The initial protocol-specific service contracts are:

- [SSH service protocol](SSH.md)
- [PKCS#11 service protocol](PKCS11.md)
- [OpenPGP service protocol](GPG.md)
- [Nostr service protocol](NOSTR.md)
- [Bitcoin service protocol](BITCOIN.md)

### KeyVault

KeyVault is the deterministic cryptographic engine.

KeyVault:

- derives keys from the configured root secret;
- executes narrowly defined cryptographic operations;
- has no user interface, network listener, or host integration;
- does not make authorization decisions;
- does not expose private key material unless an explicitly enabled
  administrative operation requires it.

KeyMaster is responsible for converting semantic requests into KeyVault paths
and function calls.

### Avatar

Avatar is KeyMaster's representative on a target host.

Avatar:

- attaches to and authenticates a KeyMaster;
- negotiates available services and capabilities;
- maintains encrypted sessions with KeyMaster;
- manages the lifecycle of service avatars on the host;
- provides a uniform local API to service avatars;
- routes requests and responses;
- handles reconnects, timeouts, cancellation, and session revocation;
- exposes no private key material.

Avatar is not the policy authority and should not implement protocol
cryptography that belongs in KeyMaster. It may enforce local restrictions, but
KeyMaster performs the final authorization.

### Service Avatars

A service avatar integrates one native host protocol with Avatar.

A service avatar:

- exposes the socket, shared library, or operating-system interface expected by
  local applications;
- implements protocol-specific session and object behavior;
- translates native requests into the uniform local Avatar API;
- translates KeyMaster results back into the native protocol;
- requests only the capabilities needed for its protocol.

Service avatars should normally run separately from the Avatar daemon. This
keeps native protocol parsers isolated and lets service avatars be installed,
restarted, or upgraded independently.

A service avatar connects only to Avatar through a local socket. It does not
authenticate KeyMaster, own a transport identity, connect to a relay, or
encrypt and sign transport messages. Avatar authenticates the local service
avatar and represents it to KeyMaster.

The corresponding protocol service inside KeyMaster trusts the KeyMaster
dispatcher to authenticate Avatar and establish the permitted realm and
service instance. Protocol services validate their own request data, but do not
independently implement Avatar-KeyMaster authentication.

Initial service avatar candidates are:

| Service avatar | Native interface | Typical clients |
|---|---|---|
| SSH agent | SSH-agent Unix socket | OpenSSH, Git |
| PKCS#11 | PKCS#11 shared library | Firefox, Brave, TLS applications |
| GnuPG | GPG-agent/scdaemon integration | GnuPG |
| Local CLI | Command-line client | Administration and diagnostics |

The PKCS#11 adapter is expected to be a thin shared library that connects to
Avatar's local API. It must not contain or derive private keys.

GnuPG integration remains an open design decision. It may use a PKCS#11 bridge
where compatible, or a dedicated GPG/Assuan adapter when OpenPGP behavior
cannot be represented correctly through PKCS#11.

## Interfaces

### Service Avatar to Avatar

Avatar exposes one uniform local API, preferably over a user-scoped Unix-domain
socket on Unix systems.

There is no connection handshake. A service avatar authenticates implicitly
through operating-system socket controls (peer credentials, socket
permissions) and declares its service type on its first request. Avatar
allocates a `serviceId` when it processes that first message and binds the
connection to `(service, serviceId)` for its lifetime. For example, the first
message from an SSH service avatar:

```json
{
  "service": "ssh",
  "requestId": "req_01J...",
  "operation": "ssh.request_identities",
  "payload": {}
}
```

Avatar authenticates the peer, reads `service`, allocates the next unused
`serviceId` for that protocol in the current realm, and wraps the request in
the common KeyMaster message envelope with the added `realmId`, `service`,
`serviceId`, and transport protection. All subsequent messages on the same
connection inherit the bound `service` and `serviceId`; the service avatar
only needs to supply `requestId`, `operation`, and `payload`.

KeyMaster repeats `realmId`, `service`, `serviceId`, and `requestId` in its
response. Avatar verifies those values against the pending request and returns
the response on the originating connection. The service avatar correlates by
`requestId`.

A service avatar connection is expected to be long-lived — typically the
entire user session. The local Unix socket survives system sleep because it
is kernel state. The connection ends only when the service avatar process
exits, Avatar shuts down, or the realm is detached. When the connection
closes, the `serviceId` is retired and never reused. A replacement service
avatar process opens a new connection and receives a new `serviceId` through
the same first-request allocation.

The local API must support request identifiers, structured errors, operation
timeouts, cancellation, and asynchronous approval states. A local socket is
not sufficient authentication by itself. Implementations should use socket
permissions, peer credentials, or equivalent platform controls.

### Avatar to KeyMaster

Avatar and KeyMaster communicate using an authenticated, encrypted, versioned
protocol.

The current transport candidate is Nostr with NIP-44 encryption. The service
model must remain independent of Nostr so that another transport can implement
the same protocol.

The protocol must support:

- attachment and mutual authentication;
- protocol and service version negotiation;
- service discovery;
- scoped service-channel creation;
- identity and capability restrictions;
- request/response correlation;
- pending approval responses;
- cancellation, expiry, detach, and revocation;
- reconnect and session recovery rules;
- explicit message-size and replay limits.

Avatar sends requests to a named, versioned KeyMaster service. It does not send
arbitrary Java method names or unrestricted KeyVault paths.

Avatar owns the transport identity for the realm. With the Nostr transport,
Avatar NIP-44 encrypts the common message envelope for KeyMaster and signs the
outer Nostr event. Individual service avatars do not have Nostr transport
identities or relay connections. KeyMaster protects replies in the reverse
direction, and Avatar verifies, decrypts, correlates, and returns each result
to the originating local socket.

### KeyMaster Transport Identity

KeyMaster's Nostr transport key is the vault-derived Nostr key for the login
identity. When KeyMaster logs in as a given identity, it derives the Nostr
keypair from the vault using the standard Nostr derivation path:

    m / 44' / 1237' / mangle(identity)' / ALG_SCHNORR' / 0'

The resulting Schnorr public key is KeyMaster's transport identity for the
session. The identity claim and the cryptographic transport key are the same
thing: Avatar verifies the attach request by checking that the sender's
public key appears in its configured allowlist. No separate identity
parameter is required in the attach message because the public key itself
identifies the caller.

Avatar must be pre-configured with the public keys it accepts. An attach
from an unknown public key is rejected before any further processing.

## Realms and Login

A realm is the outer authorization and routing boundary between one KeyMaster
and one Avatar. It is created by the Avatar-KeyMaster handshake and remains
valid until logout, revocation, or expiry.

A realm contains:

- the authenticated Avatar and KeyMaster transport identities;
- transport connection details, including the selected relay when Nostr is
  used;
- the services supported by Avatar and selected by KeyMaster;
- a primary KeyMaster identity selected during login;
- any secondary identities, accounts, or individual keys explicitly added by
  the user;
- the capabilities and policy granted to each service;
- active protocol service instances;
- expiry, revocation, and reconnect state.

The normal login selects one primary identity. KeyMaster automatically offers
the active protocol assignments belonging to that identity for services
supported by Avatar. The user may select fewer services, add secondary
identities, add an individual protocol key, or explicitly grant all eligible
identities. These additions extend only the current realm and do not change
the underlying identity configuration.

For example, if Avatar advertises SSH, OpenPGP, and Nostr, KeyMaster may log in
with one identity and select all three services. KeyMaster creates the
corresponding protocol service instances, and Avatar starts or activates the
matching local service avatars.

### Realm Handshake

Avatar publishes its transport public key, relay URL, and supported services
as an `AvatarDescriptor` (for example via QR code or a JSON file):

```json
{
  "relay": "ws://relay.example.com:7777",
  "pubkey": "64-hex-char avatar transport public key",
  "services": ["ssh", "nostr"]
}
```

KeyMaster loads the mnemonic, creates an identity, and initiates the
handshake by attaching to the descriptor:

```java
KeyMaster km = new KeyMaster(mnemonic);
km.createIdentity("alice@atlanta.com");
AvatarDescriptor avatar = AvatarDescriptor.fromFile(descriptorPath);
String sessionId = km.attach(avatar);
```

The `attach` call connects to the relay specified in the descriptor, sends
an attach request to the avatar pubkey, and includes the requested services.
On success it returns the session event ID. `detach` sends the detach
message and closes the relay connection:

```java
km.detach();
```

The handshake sequence is:

    KeyMaster -> Avatar: attach
      KeyMaster transport identity (= vault-derived Nostr pubkey for login identity)
      requested services from AvatarDescriptor
      connection details

    Avatar: verify KeyMaster pubkey against allowlist
      reject if unknown

    Avatar -> KeyMaster: attach response
      accepted services
      realm confirmation

The wire messages are NIP-44 encrypted Nostr events (kind 27235). The
KeyMaster transport public key authenticates the caller; Avatar does not
need a separate challenge-response because the NIP-44 decryption and
Schnorr signature verification on the event already prove possession of
the corresponding private key.

## Service Instances and Routing

Within a realm, every selected protocol has a one-to-one logical mapping:

```text
local service avatar connection
    <-> Avatar logical service instance
    <-> KeyMaster logical service instance
```

Each mapping receives a `serviceId` allocated by Avatar and scoped by the
realm and protocol. Initial services normally use number `0`, for example
`ssh:0`, `gpg:0`, and `nostr:0`. Additional instances use increasing numbers,
such as `ssh:1`.

The complete logical service address is:

```text
realmId / service / serviceId
```

`realmId` identifies the overall Avatar-KeyMaster relationship. `service`
identifies the protocol and message schema. `serviceId` distinguishes parallel
instances of that protocol. The service avatar creates `requestId` to
correlate one local request and response. It must be unique among outstanding
requests from that service instance.

Identifier ownership is:

| Field | Created by | Purpose |
|---|---|---|
| `realmId` | Realm handshake | Selects the Avatar-KeyMaster relationship. |
| `service` | Avatar from the authenticated socket | Selects the protocol schema. |
| `serviceId` | Avatar | Selects one protocol service instance in the realm. |
| `requestId` | Service avatar | Correlates the service's request and response. |

Avatar wraps the protocol request in a common, transport-independent envelope:

```json
{
  "version": 1,
  "type": "request",
  "realmId": "realm_01J...",
  "service": "ssh",
  "serviceId": 1,
  "requestId": "request_01J...",
  "operation": "ssh.sign",
  "expiresAt": "2026-06-15T12:00:00Z",
  "payload": {
    "keyId": "key_01J...",
    "data": "base64-encoded SSH payload",
    "flags": 0
  }
}
```

KeyMaster authenticates and decrypts the transport message and resolves its
realm and logical service address. A response repeats `realmId`, `service`,
`serviceId`, and `requestId`:

```json
{
  "version": 1,
  "type": "response",
  "realmId": "realm_01J...",
  "service": "ssh",
  "serviceId": 1,
  "requestId": "request_01J...",
  "status": "success",
  "payload": {
    "signature": "base64-encoded SSH signature blob"
  }
}
```

Avatar maintains the local routing table from `(service, serviceId)` to the
authenticated service socket. KeyMaster maintains the corresponding routing
table from `(realmId, service, serviceId)` to the protocol service instance
and its realm grant. Avatar also tracks each outstanding request against its
originating socket and identifiers. Protocol services create and consume the
operation and payload, while the Avatar and KeyMaster dispatchers add,
validate, and preserve the common routing fields.

### Implicit Service Creation

There is no separate `service.open` operation. The first protocol request for
a new `(service, serviceId)` also requests creation of that logical KeyMaster
service.

When a new service avatar connects and sends its first request, Avatar:

1. authenticates the peer via socket credentials;
2. reads the `service` field from the first message;
3. assigns the next unused `serviceId` for that protocol in the realm;
4. binds the connection to `(service, serviceId)`;
5. forwards the request with that address.

When KeyMaster receives a valid request for an unknown service address, it:

1. verifies that Avatar advertised and is permitted to run that service;
2. places the first request in a bounded pending state;
3. asks the user whether to create the new service and which identities,
   accounts, keys, capabilities, and policy it should receive;
4. creates the logical protocol service if approved;
5. processes the original request and returns its normal response.

If the user rejects the request, approval expires, or the local socket closes,
KeyMaster does not create the service and returns or records the corresponding
failure. Additional requests for the same pending service are rejected or
bounded; they must not create multiple approval prompts.

An unknown service address is therefore meaningful only when it is the first
request from a newly connected service avatar. It is not automatically trusted.
Avatar must allocate service numbers monotonically within the realm and never
reuse a closed number.

### Service Process Failure

A `serviceId` represents one service avatar connection lifetime. If the
connection closes, Avatar cancels its pending requests and marks the logical
service closed. Avatar notifies KeyMaster of the closure through the realm
control channel. A replacement service avatar receives a new `serviceId`
through the standard first-request allocation.

For example:

```text
ssh:0 active
ssh:0 connection closes -> ssh:0 retired
new SSH service avatar connects -> first request allocates ssh:1
ssh:1 request -> KeyMaster approval -> create and process
```

This deliberately avoids reconnection credentials, incarnation identifiers,
and automatic transfer of an existing grant to a replacement process.

Requests and responses may be delivered out of order. Routing therefore uses
identifiers rather than transport order. Replayed `requestId` values, expired
requests, service mismatches, and operations outside the realm grant must be
rejected.

## KeyMaster Runtime Dispatch

KeyMaster is event-driven. The two primary event sources are:

- authenticated, decrypted requests arriving from the Avatar-KeyMaster
  transport, such as Nostr events;
- completion, failure, cancellation, or timeout events from KeyVault
  operations and approval workflows.

The conceptual runtime shape is:

```text
RealmManager
  realms[realmId] -> Realm

Realm
  services[(service, serviceId)] -> ServiceInstance
  pendingRequests[requestId] -> PendingRequest
```

The global `RealmManager` owns the map of active realms. Each `Realm` owns its
own service-instance map. Within a realm, `(service, serviceId)` is the key to
the logical KeyMaster protocol service instance. This keeps realm teardown
simple: closing a realm closes every service and pending request it owns.

The request dispatch path is:

```text
transport event
 -> verify Avatar transport identity
 -> decrypt and parse envelope
 -> realm = realms[realmId]
 -> serviceInstance = realm.services[(service, serviceId)]
 -> authorize operation against the realm grant
 -> dispatch operation and payload to the protocol service
```

If `(service, serviceId)` is unknown, the implicit service-creation rules
apply before dispatching the original request.

When a protocol service starts a KeyVault operation, KeyMaster records a
pending request:

```text
PendingRequest
  realmId
  service
  serviceId
  requestId
  operation
  approval state
  KeyVault operation handle
  response deadline
```

When KeyVault or an approval workflow completes, KeyMaster uses the
`PendingRequest` to construct the response envelope with the same `realmId`,
`service`, `serviceId`, and `requestId`, then sends it back through the
Avatar-KeyMaster transport. The protocol service may be implemented as an
object, task, actor, or dispatcher entry; the architecture requires only the
routing and lifecycle behavior, not a specific collection or concurrency
primitive.

KeyMaster must remove pending requests after completion, cancellation, expiry,
realm closure, or service closure. A late KeyVault result for a removed
pending request is ignored and audited.

### KeyMaster to KeyVault

The KeyMaster-to-KeyVault boundary is a narrow execution API:

```text
execute(function, keyPath, parameters, payload) -> result
```

This boundary may initially be in-process. Its contract must permit a future
isolated process, hardware module, smart card, or other secure execution
environment.

## Service and Key Addressing

KeyMaster owns stable identifiers for:

- identities;
- services;
- configurations;
- keys;
- certificates;
- sessions.

A conceptual service address is:

```text
identity / service / configuration / key-role / key-index
```

External callers receive opaque identifiers rather than raw KeyVault
derivation paths. KeyMaster resolves those identifiers and applies policy
before invoking KeyVault.

## Identity Configuration and Key Activation

The seed defines which keys KeyVault can derive. It does not define which keys
KeyMaster exposes or permits callers to use.

KeyMaster maintains metadata for every configured identity. The metadata
records:

- the identity identifier and display metadata;
- the protocol services assigned to the identity;
- the algorithm, key role, and key index assigned to each service;
- whether each service and key assignment is active;
- protocol-specific public metadata, such as certificates or OpenPGP user IDs;
- authorization policy and allowed Avatars;
- configuration version, creation time, and modification time.

All supported protocol derivation namespaces may be technically available
from a seed, but no protocol or key becomes active merely because it can be
derived. KeyMaster services list and use only assignments marked active.
Disabling an assignment prevents new operations without changing the seed or
destroying the deterministic ability to derive the same key later.

When creating an identity, the user selects which protocols to assign to it.
For example, an identity may enable SSH and Nostr while leaving PKCS#11,
OpenPGP, and Bitcoin inactive. Each assignment selects its algorithm, key
role, key index, metadata, and policy.

Identity templates may provide reusable defaults. A template can define:

- a set of protocol assignments;
- default algorithms and key roles;
- default key indices or allocation rules;
- required protocol metadata;
- default authorization and approval policy.

Applying a template creates ordinary identity configuration records. The
identity may then override, activate, or deactivate individual assignments.
Templates do not contain seeds or private keys.

### Metadata Persistence with Nostr

KeyMaster may store and synchronize identity configuration metadata as signed,
encrypted Nostr events. This gives KeyMaster a transport-independent place to
recover configuration from one or more relays.

The persisted records must:

- be signed by an administrative KeyMaster identity;
- be encrypted for the intended KeyMaster installation or owner;
- contain stable identity, assignment, and configuration identifiers;
- include a monotonically ordered revision or an explicit predecessor;
- support revocation and tombstone records;
- exclude mnemonic phrases, seed material, private keys, and secret
  passphrases.

The Nostr relay is storage and synchronization infrastructure, not the
authority that activates keys. KeyMaster verifies signatures, encryption,
ownership, revision ordering, and policy before accepting metadata. Cached
local state remains necessary when relays are unavailable.

## Authorization and User Interaction

Authorization is part of KeyMaster, not a service avatar.

For each operation, KeyMaster evaluates:

- authenticated caller and Avatar session;
- requested service and capability;
- identity and key scope;
- operation type and algorithm;
- configured policy;
- request origin and contextual information;
- whether user authentication or approval is required.

An operation may complete immediately, be rejected, or enter a pending state:

```text
requested -> pending-approval -> approved -> completed
                              \-> rejected
                              \-> expired
                              \-> cancelled
```

A Kotlin or Android GUI is a KeyMaster user interface. It consumes pending
authorization requests, presents them to the user, performs platform
authentication where configured, and returns the decision to KeyMaster. The
GUI must call the same KeyMaster application API used by non-graphical
frontends; cryptographic policy must not be implemented in Compose screens.

## Example Flows

### SSH Signing

```text
ssh
 -> SSH-agent socket
 -> SSH service avatar
 -> Avatar local API: sign
 -> Avatar-KeyMaster SSH service request
 -> KeyMaster policy and optional approval
 -> KeyVault signing operation
 -> SSH signature response
```

### Browser Client Certificate

```text
Firefox or Brave
 -> libdwdc-pkcs11
 -> PKCS#11 service avatar
 -> Avatar local API: certificate.get or sign
 -> Avatar-KeyMaster TLS/X.509 service request
 -> KeyMaster policy and optional approval
 -> KeyVault signing operation
 -> PKCS#11 result
```

### OpenPGP Signing

```text
gpg
 -> GnuPG adapter or validated PKCS#11 bridge
 -> Avatar local API: sign
 -> Avatar-KeyMaster OpenPGP service request
 -> KeyMaster policy and optional approval
 -> KeyVault signing operation
 -> OpenPGP-compatible signature result
```

Public OpenPGP certificates, fingerprints, subkey metadata, and creation times
remain first-class metadata. KeyExporter may construct exportable OpenPGP key
rings, while runtime private-key operations remain controlled by KeyMaster.

## Security Boundaries

The architecture establishes these boundaries:

1. Applications trust their native adapter interface.
2. Service avatars authenticate to the local Avatar API and receive limited
   capabilities.
3. Avatar authenticates to KeyMaster and receives only explicitly delegated
   services.
4. KeyMaster performs authorization and user interaction.
5. KeyVault performs constrained cryptographic operations.

Compromise of an Avatar or service avatar must not reveal root secrets or
private key material. KeyMaster must be able to revoke an Avatar, an adapter
session, a service channel, or an individual capability.

## Deployment Models

Avatar is deployed as a native binary on the target host, not inside a
container. Avatar needs display access for QR presentation, filesystem access
for its local API socket, and integration with the host session lifecycle.
Container isolation works against all three requirements. Docker is retained
for E2E testing only, where the Avatar process runs inside a container with a
virtual framebuffer and the test harness connects from outside.

### Socket Architecture

Avatar exposes one Unix-domain socket: the uniform local API described in
"Service Avatar to Avatar" above. Service avatars connect to this single
socket and identify their service type during the connection handshake. The
protocol between Avatar and service avatars is the same internal envelope
format regardless of service type.

Protocol-specific sockets are a service avatar concern, not an Avatar
concern. The SSH service avatar exposes an SSH-agent socket to local
applications. The GnuPG service avatar exposes whatever interface GnuPG
requires. Avatar itself does not speak SSH-agent protocol or Assuan protocol
on any socket.

The current prototype bundles Avatar and its service avatars into one process
for development convenience. The architectural boundary remains: Avatar owns
the relay connection, transport identity, and service routing; protocol
translation belongs to service avatars.

### Deployment Phases

Deployment proceeds in three phases, each building on the previous:

**Phase 1: Interactive (current).** The user runs `keymaster-avatar` in a
terminal. QR is displayed on stdout. The local API socket is created in
`/tmp/`. The user exports the socket path and runs native protocol clients.
This phase validates the protocol stack and end-to-end flow without requiring
system integration.

**Phase 2: User service (future).** Avatar runs as a systemd `--user`
service. The local API socket moves to `$XDG_RUNTIME_DIR/keymaster-avatar/`.
A shell profile snippet or systemd environment generator sets the socket path
for service avatars. QR payload is written to a file so that a notification
tool or terminal helper can display it on demand.

**Phase 3: Login manager (future).** A PAM module and display-manager greeter
plugin present the QR and trigger Avatar attachment as part of the login flow.
Attach starts the user session; detach ends it. This phase requires
per-display-manager integration (GDM, SDDM, greetd, etc.) and careful
session-lifecycle coordination with systemd-logind.

## Decisions Still Required

The following require separate architecture decision records:

1. Local Avatar API framing, authentication, and operating-system support.
2. Final Avatar-KeyMaster message schema and service versioning.
3. Nostr event kinds, replay protection, and reconnect behavior.
4. GnuPG integration through PKCS#11 versus a dedicated Assuan adapter.
5. PKCS#11 object model, token model, and certificate provisioning.
6. KeyMaster process model on desktop, server, and Android.
7. User approval lifecycle and GUI notification mechanism.
8. Audit-log format, retention, and privacy policy.
9. Service plug-in discovery and compatibility rules.

These decisions should be recorded as versioned architecture decision records
under `doc/adr/`.
