package club.dwdc.keymaster;

/**
 * A Nostr event signing response: the 64-byte BIP-340 Schnorr signature.
 */
public record NostrSignEventResponse(byte[] signature) {
}
