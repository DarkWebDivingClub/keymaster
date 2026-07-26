package club.dwdc.keymaster;

/**
 * A Nostr decryption request (NIP-04 or NIP-44): identifies the recipient key,
 * the peer's public key, and the ciphertext to decrypt.
 */
public record NostrDecryptRequest(byte[] publicKey, byte[] peerPublicKey, String ciphertext) {
}
