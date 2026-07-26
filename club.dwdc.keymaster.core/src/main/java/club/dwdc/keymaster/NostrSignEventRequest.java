package club.dwdc.keymaster;

/**
 * A Nostr event signing request: identifies the key by public key and
 * provides a pre-hashed event ID (32 bytes) to sign with BIP-340 Schnorr.
 */
public record NostrSignEventRequest(byte[] publicKey, byte[] eventHash) {
}
