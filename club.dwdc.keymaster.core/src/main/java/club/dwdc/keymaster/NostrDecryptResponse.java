package club.dwdc.keymaster;

/**
 * A Nostr decryption response: the recovered plaintext string.
 */
public record NostrDecryptResponse(String plaintext) {
}
