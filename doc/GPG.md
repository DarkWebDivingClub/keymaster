# OpenPGP Service Protocol

Status: Draft

This document defines the first request-response contract for the OpenPGP
service between a GnuPG Avatar service and the OpenPGP KeyMaster service.

The GnuPG Avatar service exposes the local interface required by GnuPG, such
as a constrained GPG-agent/Assuan adapter. Avatar carries requests over its
single connection to KeyMaster.

## Scope

The first OpenPGP service contract has these operations:

1. `gpg.listKeys`
2. `gpg.getCertificate`
3. `gpg.sign`
4. `gpg.decrypt`

The Avatar service handles Assuan framing, local keygrip lookup, inquiry
handling, and conversion between GnuPG data types and this service contract.
KeyMaster owns key selection, authorization, user approval, OpenPGP algorithm
validation, and private-key operations.

Key generation, private-key import or export, key certification, revocation,
and smart-card administration are outside the initial scope.

## List Keys

`gpg.listKeys` returns active OpenPGP keys visible to the authenticated Avatar
session.

Request:

```json
{
  "operation": "gpg.listKeys",
  "version": 1
}
```

Response:

```json
{
  "keys": [
    {
      "keyId": "key_01J...",
      "fingerprint": "0123456789ABCDEF0123456789ABCDEF01234567",
      "keygrip": "89ABCDEF0123456789ABCDEF0123456789ABCDEF",
      "algorithm": "rsa",
      "capabilities": ["sign", "decrypt"],
      "createdAt": "2026-06-15T10:00:00Z",
      "userIds": ["Duke H3 <duke_h3@dwdc.club>"]
    }
  ]
}
```

Fields:

- `keyId` is an opaque identifier scoped to the authenticated Avatar session.
- `fingerprint` is the OpenPGP certificate or subkey fingerprint.
- `keygrip` is public lookup metadata used by GnuPG. It is not a KeyVault
  derivation path.
- `capabilities` contains only operations enabled for the active assignment.
- `userIds` are display metadata and must not be trusted as authorization
  identities.

KeyMaster filters the result using identity configuration, active OpenPGP
assignments, Avatar authorization, and current policy.

## Get Certificate

`gpg.getCertificate` returns the public OpenPGP certificate associated with a
key.

Request:

```json
{
  "operation": "gpg.getCertificate",
  "version": 1,
  "keyId": "key_01J..."
}
```

Response:

```json
{
  "keyId": "key_01J...",
  "fingerprint": "0123456789ABCDEF0123456789ABCDEF01234567",
  "certificate": "base64-encoded binary OpenPGP certificate"
}
```

The certificate contains public packets only. It may contain the primary key,
user IDs, public subkeys, and their binding signatures. It never contains
secret-key packets or KeyVault derivation metadata.

## Sign

`gpg.sign` creates OpenPGP signature material with an active signing key.

Request:

```json
{
  "operation": "gpg.sign",
  "version": 1,
  "keyId": "key_01J...",
  "publicKeyAlgorithm": "rsa",
  "hashAlgorithm": "sha256",
  "digest": "base64-encoded digest",
  "digestPrefix": "base64-encoded first two digest bytes"
}
```

Response:

```json
{
  "publicKeyAlgorithm": "rsa",
  "signatureValues": [
    "base64-encoded unsigned OpenPGP MPI"
  ]
}
```

The GnuPG adapter constructs and hashes the OpenPGP signature packet data,
including its signature type and subpackets. KeyMaster validates:

- that the digest length matches `hashAlgorithm`;
- that `digestPrefix` matches the first two digest bytes;
- that the selected key permits the requested algorithms;
- that the request is allowed by policy.

`signatureValues` contains the algorithm-specific unsigned multiprecision
integer values required by the OpenPGP signature packet. It is not a complete
OpenPGP packet. For algorithms with multiple signature values, the array
preserves the order defined by OpenPGP.

The service must not expose a generic raw private-key operation. Supported
algorithm and hash combinations must be explicitly allowlisted.

## Decrypt

`gpg.decrypt` unwraps an OpenPGP public-key-encrypted session key.

Request:

```json
{
  "operation": "gpg.decrypt",
  "version": 1,
  "keyId": "key_01J...",
  "publicKeyAlgorithm": "rsa",
  "encryptedSessionKeyValues": [
    "base64-encoded unsigned OpenPGP MPI"
  ]
}
```

Response:

```json
{
  "sessionKey": "base64-encoded OpenPGP session-key data"
}
```

KeyMaster validates the algorithm, ciphertext structure, size, selected key,
and authorization policy before decrypting. It performs the algorithm-specific
decoding and padding validation and returns only the OpenPGP session-key data
needed by the adapter.

Malformed ciphertext and padding failures must return the same externally
observable error to avoid creating a decryption oracle. Responses and timing
must not reveal which validation step failed.

## Approval

Signing or decryption may require user authentication or approval:

```text
requested -> pending-approval -> approved -> completed
                              \-> rejected
                              \-> expired
                              \-> cancelled
```

The GnuPG adapter may block while approval is pending, subject to bounded
timeouts and cancellation. Listing keys and retrieving public certificates
should normally be non-interactive.

## Error Mapping

Initial service error codes:

| Code | Meaning |
|---|---|
| `unknown-key` | The key is unavailable or outside the session scope. |
| `unsupported-algorithm` | The public-key algorithm is not supported for the key. |
| `unsupported-hash` | The requested hash algorithm is not supported. |
| `invalid-data` | The digest, MPI, or other request data is malformed. |
| `not-authorized` | Policy rejected the operation. |
| `approval-rejected` | The user rejected the operation. |
| `decryption-failed` | The ciphertext could not be safely decrypted or decoded. |
| `expired` | The request or approval expired. |
| `cancelled` | The caller cancelled the request. |
| `service-unavailable` | Avatar cannot currently reach the OpenPGP service. |

The adapter maps these errors to valid GPG-agent/Assuan errors without
revealing hidden keys, policy details, padding state, or private metadata.

## Security Requirements

- Secret keys, seeds, passphrases, and derivation paths never leave KeyMaster
  and KeyVault.
- KeyMaster authorizes every signing and decryption request independently.
- Public-key algorithms, hash algorithms, MPI counts, and input sizes are
  strictly validated and bounded.
- Decryption failures do not reveal padding or session-key parsing details.
- Public certificate caches are invalidated when assignments change or the
  Avatar session is revoked.
- Audit records include the Avatar, key, operation, algorithms, decision, and
  timestamp, but not plaintext session keys or complete signed data.
