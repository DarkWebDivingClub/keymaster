# SSH Service Protocol

Status: Draft

This document defines the first request-response contract for the SSH service
between an SSH Avatar service and the SSH KeyMaster service.

The SSH Avatar service exposes a standard SSH-agent socket to local
applications. Avatar carries the requests over the single connection to
KeyMaster described in [ARCHITECTURE.md](ARCHITECTURE.md).

## Scope

The first version supports the two SSH-agent operations that require
KeyMaster:

1. `ssh.listIdentities`
2. `ssh.sign`

The Avatar service handles SSH-agent framing and message types locally.
KeyMaster owns key selection, authorization, user approval, and private-key
operations.

Adding, removing, locking, or exporting private keys is not supported.
Unsupported SSH-agent requests return the standard SSH-agent failure response.

## List Identities

`ssh.listIdentities` returns the SSH public identities available to the
authenticated Avatar session.

Request:

```json
{
  "operation": "ssh.listIdentities",
  "version": 1
}
```

Response:

```json
{
  "identities": [
    {
      "keyId": "key_01J...",
      "keyBlob": "base64-encoded SSH public-key blob",
      "comment": "duke_h3@dwdc.club"
    }
  ]
}
```

Fields:

- `keyId` is an opaque KeyMaster identifier. It is not a KeyVault derivation
  path.
- `keyBlob` is the complete SSH wire-format public-key blob expected by the
  SSH-agent protocol.
- `comment` is display metadata and has no security meaning.

KeyMaster filters the result using the authenticated Avatar, identity,
service configuration, and current policy.

## Sign

`ssh.sign` signs the exact SSH payload supplied by the SSH client.

Request:

```json
{
  "operation": "ssh.sign",
  "version": 1,
  "keyId": "key_01J...",
  "keyBlob": "base64-encoded SSH public-key blob",
  "data": "base64-encoded bytes to sign",
  "flags": 4
}
```

Response:

```json
{
  "signature": "base64-encoded SSH signature blob"
}
```

Fields:

- `keyId` selects an identity returned by `ssh.listIdentities`.
- `keyBlob` binds the request to the public key selected by the SSH client.
  KeyMaster must verify that it matches `keyId`.
- `data` contains the exact byte string from the SSH-agent sign request.
- `flags` contains the SSH-agent signature flags. In particular, RSA flags
  select `rsa-sha2-256` or `rsa-sha2-512`.
- `signature` is the complete SSH wire-format signature blob, including its
  SSH algorithm identifier.

KeyMaster must validate that the requested algorithm is compatible with the
selected key. It must never accept a caller-provided KeyVault path.

## Approval

A sign request may require user authentication or approval. The request then
enters the common pending state defined by the architecture:

```text
requested -> pending-approval -> approved -> completed
                              \-> rejected
                              \-> expired
                              \-> cancelled
```

The Avatar service waits for the final response subject to its configured
timeout. Listing identities should normally be non-interactive.

## Error Mapping

The service returns structured errors to Avatar. The SSH Avatar service maps
all failures to valid SSH-agent responses.

Initial error codes:

| Code | Meaning |
|---|---|
| `unsupported-operation` | The SSH-agent operation is not implemented. |
| `unknown-key` | The requested key is unavailable or outside the session scope. |
| `key-mismatch` | `keyBlob` does not match `keyId`. |
| `unsupported-algorithm` | The key cannot use the requested signature algorithm. |
| `not-authorized` | Policy rejected the operation. |
| `approval-rejected` | The user rejected the operation. |
| `expired` | The request or approval expired. |
| `cancelled` | The caller cancelled the request. |
| `service-unavailable` | Avatar cannot currently reach the SSH service. |

Error details exposed to an untrusted local caller must not reveal hidden
identities or policy configuration.

## Security Requirements

- Private keys, seeds, and derivation paths never leave KeyMaster and
  KeyVault.
- Avatar must correlate each response with the originating local connection
  and request.
- KeyMaster must authorize every sign request independently.
- Message size and signing timeouts must be bounded.
- Audit records should include the Avatar, key, algorithm, decision, and
  timestamp, but not the complete data being signed.
