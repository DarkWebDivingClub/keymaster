# PKCS#11 Service Protocol

Status: Draft

This document defines the first request-response contract for the PKCS#11
service between a PKCS#11 Avatar service and the PKCS#11 KeyMaster service.

The PKCS#11 Avatar service is expected to be a Rust shared library loaded by
applications such as Firefox or Brave. It exposes the standard PKCS#11 C API
locally and communicates with Avatar through the local Avatar socket. Avatar
uses its single connection to KeyMaster.

## Design Boundary

PKCS#11 has a large stateful API covering slots, sessions, object searches,
attributes, login state, and cryptographic operations. These native mechanics
must not become one remote operation per PKCS#11 C function.

The first PKCS#11 service contract has these operations:

1. `pkcs11.open`
2. `pkcs11.describeToken`
3. `pkcs11.listObjects`
4. `pkcs11.getObject`
5. `pkcs11.login`
6. `pkcs11.sign`
7. `pkcs11.logout`
8. `pkcs11.close`

These are service-level operations. They do not mirror every native PKCS#11 C
function. The Rust adapter still implements native session handles, object
handles, search cursors, attribute projection, and multipart buffering
locally.

## Open

`pkcs11.open` establishes a scoped PKCS#11 service session.

Request:

```json
{
  "operation": "pkcs11.open",
  "version": 1,
  "adapter": "dwdc-pkcs11",
  "requestedCapabilities": [
    "objects.read",
    "sign"
  ]
}
```

Response:

```json
{
  "sessionId": "session_01J...",
  "capabilities": [
    "objects.read",
    "sign"
  ]
}
```

The service session is distinct from native `CK_SESSION_HANDLE` values. The
adapter may expose many local PKCS#11 sessions over one scoped service
session.

## Describe Token

`pkcs11.describeToken` returns token metadata and supported mechanisms.

Request:

```json
{
  "operation": "pkcs11.describeToken",
  "version": 1,
  "sessionId": "session_01J..."
}
```

Response:

```json
{
  "token": {
    "label": "DWDC KeyMaster",
    "manufacturer": "DWDC",
    "model": "Avatar",
    "serialNumber": "avatar-01",
    "protectedAuthenticationPath": true
  },
  "mechanisms": [
    {
      "name": "CKM_ECDSA",
      "canSign": true,
      "minimumKeySize": 256,
      "maximumKeySize": 521
    }
  ]
}
```

## PKCS#11 Identity

One PKCS#11 identity represents the objects needed for a client certificate:

- one X.509 certificate object;
- one public-key object;
- one private-key reference.

The three local objects use the same `CKA_ID`. The private-key object contains
only a reference to a KeyMaster key. It never contains extractable private-key
material.

## Mapping KeyMaster Identities to Tokens

KeyVault can technically derive keys for every supported protocol, algorithm,
and key index from an identity seed. PKCS#11 must not expose every derivable
key.

KeyMaster metadata determines which protocol assignments are active for an
identity. A PKCS#11 token is a configured view containing only active PKCS#11
assignments:

```text
seed
  -> KeyMaster identity
    -> active PKCS#11 token configuration
      -> algorithm + key role + key index
        -> certificate object
        -> public-key object
        -> private-key reference
```

The mapping is:

- the seed is the private root from which KeyVault can derive keys;
- the KeyMaster identity owns configuration and public metadata;
- the token is a configured collection of active PKCS#11 keys;
- the protocol selects the PKCS#11 derivation namespace;
- the algorithm selects the key type and permitted mechanisms;
- the key role and key index select a particular deterministic key;
- `CKA_ID` links the certificate, public-key, and private-key-reference
  objects for that key;
- the token serial number identifies the token configuration and is not
  derived from the seed.

Creating an identity does not automatically create or populate a PKCS#11
token. The user must assign PKCS#11 to the identity, either directly or through
an identity template, and activate the required keys. A template may select
default algorithms, roles, indices, certificate requirements, and approval
policy.

`pkcs11.describeToken`, `pkcs11.listObjects`, and `pkcs11.getObject` return
only active assignments allowed for the current Avatar session. Deactivating
an assignment removes its objects from new listings and prevents new signing
operations. It does not delete the seed or alter deterministic key derivation.

KeyMaster may persist this activation metadata as signed, encrypted Nostr
events as described in [ARCHITECTURE.md](ARCHITECTURE.md). The relay never
receives private key material and does not decide which assignments are
active.

## List Objects

`pkcs11.listObjects` returns summaries of the objects visible in the service
session. It supports the object classes and common search attributes needed by
the native `C_FindObjects` flow.

Request:

```json
{
  "operation": "pkcs11.listObjects",
  "version": 1,
  "sessionId": "session_01J...",
  "filter": {
    "class": "CKO_CERTIFICATE"
  }
}
```

Response:

```json
{
  "objects": [
    {
      "objectId": "object_01J...",
      "class": "CKO_CERTIFICATE",
      "ckaId": "base64-encoded stable object identifier",
      "label": "duke_h3@dwdc.club"
    }
  ]
}
```

Fields:

- `objectId` is an opaque identifier valid within the service session.
- `ckaId` is the stable value the adapter exposes as `CKA_ID` on the
  certificate, public-key, and private-key-reference objects.
- `class` identifies a certificate, public-key, or private-key-reference
  object.

KeyMaster applies authorization before returning object summaries. A filter is
a constrained structured query, not an arbitrary expression.

## Get Object

`pkcs11.getObject` returns the permitted attributes and public value of one
object.

Request:

```json
{
  "operation": "pkcs11.getObject",
  "version": 1,
  "sessionId": "session_01J...",
  "objectId": "object_01J..."
}
```

Certificate response:

```json
{
  "objectId": "object_01J...",
  "class": "CKO_CERTIFICATE",
  "ckaId": "base64-encoded stable object identifier",
  "label": "duke_h3@dwdc.club",
  "certificateType": "CKC_X_509",
  "value": "base64-encoded DER X.509 certificate"
}
```

Public-key response:

```json
{
  "objectId": "object_01K...",
  "class": "CKO_PUBLIC_KEY",
  "ckaId": "base64-encoded stable object identifier",
  "label": "duke_h3@dwdc.club",
  "keyType": "CKK_EC",
  "subjectPublicKeyInfo": "base64-encoded DER SubjectPublicKeyInfo"
}
```

Private-key-reference response:

```json
{
  "objectId": "object_01M...",
  "class": "CKO_PRIVATE_KEY",
  "ckaId": "base64-encoded stable object identifier",
  "label": "duke_h3@dwdc.club",
  "keyType": "CKK_EC",
  "sensitive": true,
  "extractable": false,
  "canSign": true
}
```

`pkcs11.getObject` never returns private-key material or a KeyVault derivation
path.

## Login

`pkcs11.login` requests authorization for private operations in the service
session.

Request:

```json
{
  "operation": "pkcs11.login",
  "version": 1,
  "sessionId": "session_01J...",
  "userType": "CKU_USER"
}
```

Response:

```json
{
  "authenticated": true,
  "expiresAt": "2026-06-14T12:30:00Z"
}
```

The browser PIN must not be the KeyMaster password, seed password, or mnemonic
passphrase. With a protected authentication path, KeyMaster performs user
authentication on its own trusted interface. Login may establish a
time-limited authorization state, but KeyMaster still evaluates policy for
each signing request.

## Sign

`pkcs11.sign` performs the private-key operation represented by PKCS#11
`C_Sign`.

Request:

```json
{
  "operation": "pkcs11.sign",
  "version": 1,
  "sessionId": "session_01J...",
  "objectId": "object_01M...",
  "mechanism": {
    "name": "CKM_ECDSA",
    "parameters": null
  },
  "data": "base64-encoded bytes supplied to C_Sign"
}
```

Response:

```json
{
  "signature": "base64-encoded PKCS#11 mechanism result"
}
```

The meaning of `data` and the signature encoding are defined by the selected
PKCS#11 mechanism. The protocol must not ambiguously label the input as a
digest:

- a raw mechanism may expect a digest or encoded block;
- a combined mechanism may hash the supplied message before signing;
- EdDSA mechanisms sign according to their mechanism parameters.

KeyMaster validates the mechanism and parameters against the identity's
allowlist. The adapter must not transform the returned signature unless the
PKCS#11 mechanism specification requires a native representation different
from the KeyVault result.

For multipart PKCS#11 signing, the first adapter version buffers bounded input
locally and sends one `pkcs11.sign` request when `C_SignFinal` is called.

## Logout

`pkcs11.logout` clears the service session's login authorization.

```json
{
  "operation": "pkcs11.logout",
  "version": 1,
  "sessionId": "session_01J..."
}
```

The adapter also updates all corresponding local PKCS#11 sessions. Logout
does not close the service session or remove public objects.

## Close

`pkcs11.close` releases the scoped service session and its object identifiers.

```json
{
  "operation": "pkcs11.close",
  "version": 1,
  "sessionId": "session_01J..."
}
```

Avatar and KeyMaster must also expire the session after disconnect,
revocation, or inactivity. Closing a service session invalidates its
`objectId` values.

## Local Adapter Responsibilities

The PKCS#11 Avatar service handles these operations without forwarding each
one to KeyMaster:

- module initialization and finalization;
- slot and token enumeration;
- native session-handle allocation and release;
- mapping native login state to the service session;
- object handles and object search state;
- mapping `C_FindObjects` to `pkcs11.listObjects`;
- mapping `C_GetAttributeValue` to cached `pkcs11.getObject` data;
- multipart input buffering;
- PKCS#11 return-code mapping.

Login is an application-facing authorization hint, not access to the
KeyMaster seed or device password. When supported, the token should advertise
a protected authentication path so secrets are not typed into an untrusted
application. KeyMaster policy remains authoritative for every sign request.

## Approval

A sign request may require user authentication or approval in KeyMaster.
The PKCS#11 call may block while the request is pending, subject to a bounded
timeout and cancellation behavior.

Object listing and public attribute reads should normally be non-interactive.
Policy may hide an identity entirely from an unauthorized Avatar.

## Error Mapping

Initial service errors map to PKCS#11 return values in the Rust adapter:

| Service code | Typical PKCS#11 result |
|---|---|
| `invalid-session` | `CKR_SESSION_HANDLE_INVALID` |
| `unknown-object` | `CKR_OBJECT_HANDLE_INVALID` |
| `unknown-key` | `CKR_KEY_HANDLE_INVALID` |
| `unsupported-mechanism` | `CKR_MECHANISM_INVALID` |
| `invalid-mechanism-parameters` | `CKR_MECHANISM_PARAM_INVALID` |
| `invalid-data` | `CKR_DATA_INVALID` or `CKR_DATA_LEN_RANGE` |
| `not-authorized` | `CKR_USER_NOT_LOGGED_IN` or `CKR_FUNCTION_REJECTED` |
| `approval-rejected` | `CKR_FUNCTION_REJECTED` |
| `expired` | `CKR_FUNCTION_CANCELED` |
| `cancelled` | `CKR_FUNCTION_CANCELED` |
| `service-unavailable` | `CKR_DEVICE_ERROR` |

The exact mapping is part of the adapter contract and must be tested against
the target applications.

## Initial Scope

The first implementation targets browser TLS client authentication:

- expose configured X.509 client certificates;
- expose matching public and private-key-reference objects;
- advertise only mechanisms implemented end to end;
- sign TLS authentication inputs after KeyMaster authorization.

Decrypt, key agreement, key generation, object creation, object destruction,
and private-key import or export are outside the initial scope. They should be
added only for a concrete client use case and as explicit service operations.

## Security Requirements

- Private-key objects are always non-extractable and sensitive.
- Private keys, seeds, PINs, and KeyVault derivation paths never reach the
  Avatar service.
- KeyMaster authorizes each sign operation independently of local PKCS#11
  login state.
- Mechanism parameters and input sizes must be strictly validated and bounded.
- Cached certificates and public keys must be invalidated when the Avatar
  session is revoked or identity configuration changes.
- Audit records should include the Avatar, key, mechanism, decision, and
  timestamp, but not the complete data being signed.
