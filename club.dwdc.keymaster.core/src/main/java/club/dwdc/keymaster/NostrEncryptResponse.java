package club.dwdc.keymaster;

/**
 * A Nostr encryption response: the ciphertext string.
 * For NIP-04: {@code base64(ciphertext)?iv=base64(iv)}.
 * For NIP-44: base64-encoded NIP-44 payload.
 */
public record NostrEncryptResponse(String ciphertext) {
}
