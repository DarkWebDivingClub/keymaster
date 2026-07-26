package club.dwdc.keymaster;

public record MlsNextInitKeyRequest(byte[] mlsPubkey, byte[] currentHpkePubkey) {
}
