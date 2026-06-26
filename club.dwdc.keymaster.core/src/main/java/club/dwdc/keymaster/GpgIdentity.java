package club.dwdc.keymaster;

/**
 * A GPG identity: key type, raw Ed25519 public key, and a human-readable label.
 */
public record GpgIdentity(String keyType, byte[] publicKey, String label) {
}
