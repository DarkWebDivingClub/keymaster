package club.dwdc.keymaster;

/**
 * A Nostr public key entry returned by {@code get_public_keys}.
 */
public record NostrPublicKey(byte[] publicKey) {
}
