# Nostr Service Protocol

Status: Draft

This document defines the first request-response contract for the Nostr
service between a Nostr Avatar service and the Nostr KeyMaster service.

The Nostr Avatar service integrates local Nostr clients with Avatar. Avatar
uses its single connection to KeyMaster. Relay connections and relay protocol
messages remain outside this service contract.

## Scope

The first Nostr service contract has these operations:

1. `nostr.listIdentities`
2. `nostr.signEvent`
3. `nostr.nip44Encrypt`
4. `nostr.nip44Decrypt`

KeyMaster owns identity selection, canonical NIP-01 event serialization,
authorization, user approval, Schnorr signing, and NIP-44 cryptography.

Relay discovery, subscriptions, event storage, publishing, and contact-list
management are handled by the Nostr client or Avatar service.

## List Identities

`nostr.listIdentities` returns active Nostr identities visible to the
authenticated Avatar session.

Request:

```json
{
  "operation": "nostr.listIdentities",
  "version": 1
}
```

Response:

```json
{
  "identities": [
    {
      "identityId": "identity_01J...",
      "pubkey": "64 lowercase hexadecimal characters",
      "name": "duke_h3",
      "capabilities": ["event.sign", "nip44.encrypt", "nip44.decrypt"]
    }
  ]
}
```

`identityId` is an opaque KeyMaster identifier. `pubkey` is the 32-byte
x-only secp256k1 public key encoded as lowercase hexadecimal. Display metadata
has no security meaning.

## Sign Event

`nostr.signEvent` validates, serializes, hashes, and signs an unsigned NIP-01
event.

Request:

```json
{
  "operation": "nostr.signEvent",
  "version": 1,
  "identityId": "identity_01J...",
  "event": {
    "created_at": 1781517600,
    "kind": 1,
    "tags": [],
    "content": "hello"
  }
}
```

Response:

```json
{
  "event": {
    "id": "64 lowercase hexadecimal characters",
    "pubkey": "64 lowercase hexadecimal characters",
    "created_at": 1781517600,
    "kind": 1,
    "tags": [],
    "content": "hello",
    "sig": "128 lowercase hexadecimal characters"
  }
}
```

KeyMaster inserts the public key selected by `identityId`, performs canonical
NIP-01 serialization, computes the event ID, and creates the BIP-340 Schnorr
signature. The caller must not supply `id`, `pubkey`, or `sig`.

Accepting the semantic event rather than only a caller-provided hash allows
KeyMaster to enforce policy using the event kind, tags, timestamp, recipients,
and content size. KeyMaster must reject duplicate JSON fields, malformed tags,
timestamps outside configured bounds, and event kinds not permitted by the
identity policy.

## NIP-44 Encrypt

`nostr.nip44Encrypt` encrypts UTF-8 content using NIP-44 version 2.

Request:

```json
{
  "operation": "nostr.nip44Encrypt",
  "version": 1,
  "identityId": "identity_01J...",
  "recipientPubkey": "64 lowercase hexadecimal characters",
  "plaintext": "secret message"
}
```

Response:

```json
{
  "version": 2,
  "payload": "base64-encoded NIP-44 payload"
}
```

KeyMaster validates the recipient public key, derives the conversation key,
generates a fresh cryptographically secure nonce, applies NIP-44 padding and
encryption, and returns the versioned payload.

The caller places the payload into an appropriate event and obtains a
signature with `nostr.signEvent`. NIP-44 does not itself define an event kind.

## NIP-44 Decrypt

`nostr.nip44Decrypt` verifies a signed NIP-01 event and decrypts its NIP-44
content for the selected identity.

Request:

```json
{
  "operation": "nostr.nip44Decrypt",
  "version": 1,
  "identityId": "identity_01J...",
  "event": {
    "id": "64 lowercase hexadecimal characters",
    "pubkey": "64 lowercase hexadecimal characters",
    "created_at": 1781517600,
    "kind": 1059,
    "tags": [],
    "content": "base64-encoded NIP-44 payload",
    "sig": "128 lowercase hexadecimal characters"
  }
}
```

Response:

```json
{
  "plaintext": "secret message"
}
```

Before decryption, KeyMaster verifies canonical NIP-01 serialization, the
event ID, and the Schnorr signature. It then uses the verified event author's
public key as the NIP-44 peer key. The service must not accept a separate peer
key that could disagree with the signed event.

The initial contract supports NIP-44 version 2 only. Payload sizes, plaintext
sizes, public keys, MACs, and padding are strictly validated.

## Approval

Event signing, encryption, or decryption may require user authentication or
approval. Policies may distinguish event kinds, recipients, content sizes,
and operation types.

Listing identities should normally be non-interactive. All operations use the
common pending state and bounded timeout and cancellation behavior.

## Error Mapping

Initial service error codes:

| Code | Meaning |
|---|---|
| `unknown-identity` | The identity is unavailable or outside the session scope. |
| `invalid-event` | Event fields, serialization, ID, or signature are invalid. |
| `unsupported-kind` | Policy does not permit the requested event kind. |
| `invalid-public-key` | A peer public key is malformed or invalid. |
| `unsupported-encryption-version` | The NIP-44 payload version is unsupported. |
| `invalid-payload` | The encrypted payload, MAC, or padding is invalid. |
| `not-authorized` | Policy rejected the operation. |
| `approval-rejected` | The user rejected the operation. |
| `expired` | The request or approval expired. |
| `cancelled` | The caller cancelled the request. |
| `service-unavailable` | Avatar cannot currently reach the Nostr service. |

Error details exposed to an untrusted caller must not reveal hidden
identities, conversation keys, policy configuration, or decryption internals.

## Security Requirements

- Private keys, seeds, conversation keys, and derivation paths never leave
  KeyMaster and KeyVault.
- KeyMaster authorizes every operation independently.
- `nostr.signEvent` accepts semantic event fields, not an arbitrary digest.
- NIP-01 event signatures are verified before NIP-44 decryption.
- Encryption uses a fresh CSPRNG nonce for every payload.
- Event, tag, content, plaintext, and payload sizes are bounded.
- Relay transport keys and Nostr identity keys are separate assignments unless
  configuration explicitly selects the same identity.
- Audit records include the Avatar, identity, operation, event kind or peer,
  decision, and timestamp, but not plaintext or complete event content.
