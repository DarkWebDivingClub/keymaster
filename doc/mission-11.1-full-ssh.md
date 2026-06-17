# Mission 11.1: Full SSH Login E2E Test

## Context

Mission 11 (Phase A) establishes the Cargo workspace split and plumbing
verification — `ssh-add -l` through the full chain proves messages route
correctly. Mission 11.1 adds the final piece: actual SSH login to a
separate Docker container.

## Prerequisites (completed in Mission 11)

- Cargo workspace: avatar, avatar-protocol, ssh-service-avatar
- Local API socket between avatar and ssh-service-avatar
- Java KM handles `service.spawn` for SSH service
- Java KM implements `ssh.listIdentities` returning Ed25519 pubkey from KV
- `ssh-add -l` shows the key through the full chain

## What This Mission Adds

### 1. Java KM: Implement `ssh.sign`

Handle sign requests routed from avatar through the SSH service channel:

- Receive `ssh.sign` request with `keyId`, `keyBlob`, `data`, `flags`
- Validate `keyBlob` matches `keyId`
- Derive Ed25519 seed from KeyVault: `vault.execute(FN_SIGN, data, path)`
  - Path: `m/44'/1238'/identity'/ALG_ED25519_USER_AUTH'/DEFAULT_CONFIG'`
- Return SSH signature blob (Ed25519, 64 bytes)

Reference: `/home/rene/git/club.dwdc.keymaster/doc/SSH.md`

### 2. SSH Target Docker Container

Add an `sshd` container to the e2e test infrastructure:

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server && rm -rf /var/lib/apt/lists/*
RUN mkdir /run/sshd
RUN useradd -m testuser
COPY authorized_keys /home/testuser/.ssh/authorized_keys
RUN chown -R testuser:testuser /home/testuser/.ssh && chmod 700 /home/testuser/.ssh && chmod 600 /home/testuser/.ssh/authorized_keys
CMD ["/usr/sbin/sshd", "-D", "-e"]
```

The `authorized_keys` file must contain the Ed25519 public key derived from
the test mnemonic for the test identity. This key is deterministic:

- Mnemonic: `abandon abandon abandon ... about` (standard test mnemonic)
- Identity: whatever test identity string is used in the e2e test
- Path: `m/44'/1238'/mangle(identity)'/ALG_ED25519(role=0)'/DEFAULT_CONFIG'`
- Output: `ssh-ed25519 <base64-pubkey> <comment>`

The public key can be pre-computed since it's deterministic from the test
mnemonic, or generated at container build time using a small Java tool.

### 3. E2E Test: `sshLoginToRemoteHost`

```java
@Test
void sshLoginToRemoteHost() throws Exception {
    // 1. Attach KM to avatar with SSH service
    km.attach(avatar, List.of("ssh"));
    Thread.sleep(3000); // Wait for service.spawn + listIdentities

    // 2. Verify key is available
    var listResult = avatar.execInContainer("ssh-add", "-l");
    assertEquals(0, listResult.getExitCode(), "ssh-add -l should show keys");

    // 3. SSH login to target container
    var sshResult = avatar.execInContainer(
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "IdentityAgent=/tmp/keymaster-avatar-ssh-agent.sock",
        "testuser@sshd-target",
        "echo", "hello"
    );
    assertEquals(0, sshResult.getExitCode(), "SSH login should succeed");
    assertTrue(sshResult.getStdout().contains("hello"));

    // 4. Cleanup
    km.detach(avatar);
}
```

### 4. Network Setup

Both the avatar container and sshd-target container must be on the same
Docker network. Testcontainers supports this via `Network.newNetwork()`.

## Key Derivation Details

### Ed25519 SSH Key from KeyVault

```
BIP-32 path: m / 44' / 1238' / identity' / alg' / config'
  44'     = BIP-44 purpose
  1238'   = SSH coin type (Protocol.SSH.coinType())
  identity' = Bip32KeyDerivator.mangle(identityString) | H
  alg'    = AlgField(ALG_ED25519=1, variant=0, role=0=user-auth) | H
  config' = ConfigField(csprng=0, index=0) | H
```

### KeyVault Operations

- `FN_EXPORT_SEED (0)`: Returns 32-byte Ed25519 seed
- `FN_GET_PUBLIC_KEY (1)`: Returns 32-byte Ed25519 public key
- `FN_SIGN (2)`: Signs message, returns 64-byte Ed25519 signature

### Reference Implementations

- Key derivation: `Bip32SshKeyDerivationTest.java` in
  `/home/rene/git/ae.redtoken.iz.keyvault.e2etest/ae.redtoken.iz.keyvault.e2etest.ssh/`
- Key export: `OpenSshKeyWriter.java` in same module
- SSH auth test: `deterministicKeyAuthenticatesOverSsh()` in `SshConnectionTest.java`
- SSH protocol spec: `/home/rene/git/club.dwdc.keymaster/doc/SSH.md`

## Files to Create/Modify

| File | Action |
|------|--------|
| `KeyMaster.java` | Add `ssh.sign` handling |
| `docker/sshd/Dockerfile` | Create SSH target container |
| `docker/sshd/authorized_keys` | Pre-computed test pubkey |
| `KeyMasterAvatarTest.java` | Add `sshLoginToRemoteHost` test |

## Verification

- `mvn test` — `sshLoginToRemoteHost` passes
- SSH login succeeds through full chain: ssh client → ssh-service-avatar →
  local API → avatar → Nostr → KM → KeyVault → Ed25519 sign → back
