package club.dwdc.keymaster;

/**
 * A Nostr encryption request (NIP-04 or NIP-44): identifies the sender key,
 * the peer's public key, and the plaintext to encrypt.
 */
public record NostrEncryptRequest(byte[] publicKey, byte[] peerPublicKey, String plaintext) {
}
