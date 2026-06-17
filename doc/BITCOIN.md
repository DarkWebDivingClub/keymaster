# Bitcoin Service Protocol

Status: Draft

This document defines the first request-response contract for the Bitcoin
service between a Bitcoin Avatar service and the Bitcoin KeyMaster service.

The Bitcoin Avatar service integrates a wallet with Avatar. Avatar carries
requests over its single connection to KeyMaster. Network access, blockchain
state, transaction construction, coin selection, and broadcasting remain
wallet responsibilities.

## Scope

The first Bitcoin service contract has these operations:

1. `bitcoin.listAccounts`
2. `bitcoin.getDescriptor`
3. `bitcoin.signPsbt`

The service uses Partially Signed Bitcoin Transactions so KeyMaster receives
the transaction, prevout information, derivation claims, and signing context
needed to validate policy. The service does not expose arbitrary digest
signing.

Address generation, balance lookup, fee estimation, coin selection,
broadcasting, private-key import or export, and seed backup are outside the
service contract.

## List Accounts

`bitcoin.listAccounts` returns active Bitcoin accounts visible to the
authenticated Avatar session.

Request:

```json
{
  "operation": "bitcoin.listAccounts",
  "version": 1
}
```

Response:

```json
{
  "accounts": [
    {
      "accountId": "account_01J...",
      "label": "Personal",
      "network": "bitcoin",
      "scriptTypes": ["p2wpkh"],
      "capabilities": ["descriptor.read", "psbt.sign"]
    }
  ]
}
```

`accountId` is an opaque KeyMaster identifier. The network is part of the
account configuration and must be one of the explicitly supported Bitcoin
networks. KeyMaster returns only active assignments allowed for the Avatar
session.

## Get Descriptor

`bitcoin.getDescriptor` returns a watch-only output descriptor for an active
account.

Request:

```json
{
  "operation": "bitcoin.getDescriptor",
  "version": 1,
  "accountId": "account_01J..."
}
```

Response:

```json
{
  "accountId": "account_01J...",
  "network": "bitcoin",
  "externalDescriptor": "wpkh([fingerprint/path]xpub.../0/*)#checksum",
  "internalDescriptor": "wpkh([fingerprint/path]xpub.../1/*)#checksum",
  "range": {
    "start": 0,
    "end": 999
  }
}
```

Descriptors contain public extended keys and origin information sufficient
for the wallet to derive addresses and recognize outputs. They never contain
private extended keys or an unrestricted KeyVault derivation path.

The configured descriptor defines the scripts, key origins, derivation range,
and signing keys that KeyMaster will accept. Returning a descriptor is an
explicit watch-only capability and may be disabled for assignments that must
not expose an extended public key.

## Sign PSBT

`bitcoin.signPsbt` validates and signs inputs belonging to an active account.

Request:

```json
{
  "operation": "bitcoin.signPsbt",
  "version": 1,
  "accountId": "account_01J...",
  "network": "bitcoin",
  "psbt": "base64-encoded PSBT",
  "signingMode": "configured-inputs"
}
```

Response:

```json
{
  "psbt": "base64-encoded PSBT containing added partial signatures",
  "signedInputs": [0]
}
```

KeyMaster parses the PSBT and independently validates:

- the transaction and every input and output;
- the network and account configuration;
- witness and non-witness UTXO consistency;
- scripts, amounts, sighash types, and key-origin claims;
- that each selected input belongs to the configured descriptor;
- fees, destinations, change outputs, and policy limits;
- that the requested signing algorithm and script type are supported.

KeyMaster adds signatures only for inputs controlled by the selected account
and returns an updated PSBT. It does not finalize or broadcast the
transaction. Unknown PSBT fields must be preserved unless they violate a
validation rule.

`signingMode: "configured-inputs"` means KeyMaster signs every eligible input
permitted by policy. Future versions may add explicit input selection, but
the caller must never select a private key or supply a KeyVault path.

The implementation must explicitly declare which PSBT versions, script types,
sighash modes, and signature algorithms it supports. Unsupported combinations
are rejected rather than partially interpreted.

## Approval

PSBT signing may require user authentication or approval. The approval UI
should show validated transaction facts, including:

- total input and output amounts;
- fee and fee rate when computable;
- external destinations;
- recognized change outputs;
- unusual sighash modes or policy warnings.

Account listing and watch-only descriptor retrieval should normally be
non-interactive. Signing uses the common pending state and bounded timeout and
cancellation behavior.

## Error Mapping

Initial service error codes:

| Code | Meaning |
|---|---|
| `unknown-account` | The account is unavailable or outside the session scope. |
| `network-mismatch` | The request network does not match the account. |
| `invalid-psbt` | The PSBT is malformed, inconsistent, or missing required data. |
| `unsupported-psbt-version` | The PSBT version is not implemented. |
| `unsupported-script` | An input uses an unsupported script type. |
| `unsupported-sighash` | A requested sighash mode is not permitted. |
| `key-origin-mismatch` | A key origin does not match the configured descriptor. |
| `policy-violation` | Transaction amounts, fees, destinations, or other facts violate policy. |
| `not-authorized` | Policy rejected the operation. |
| `approval-rejected` | The user rejected the operation. |
| `expired` | The request or approval expired. |
| `cancelled` | The caller cancelled the request. |
| `service-unavailable` | Avatar cannot currently reach the Bitcoin service. |

Error details exposed to an untrusted wallet must not reveal hidden accounts,
unused keys, policy thresholds, or private derivation metadata.

## Initial Scope

The first implementation should enable only a deliberately small set of
descriptor and script types that are tested end to end. A reasonable initial
target is single-key SegWit accounts represented by descriptors and PSBT.

Multisignature, Taproot script paths, Miniscript policies, MuSig2, Lightning
transactions, message signing, and arbitrary scripts are outside the initial
scope unless added as explicit, tested capabilities.

## Security Requirements

- Private keys, seeds, private extended keys, and unrestricted derivation paths
  never leave KeyMaster and KeyVault.
- KeyMaster parses and authorizes the complete PSBT before signing any input.
- The service never signs an arbitrary caller-provided digest.
- Descriptor ownership and PSBT key-origin claims are independently verified.
- Transaction, script, map, and field sizes are strictly bounded.
- Signing is atomic from a policy perspective: KeyMaster must not leak useful
  partial results after approval or validation fails.
- Audit records include the Avatar, account, transaction identifier when
  available, signed input indices, amounts, fee, decision, and timestamp, but
  not private key material.
