package club.dwdc.keymaster;

public record MlsPublicKeyRequest(byte[] nostrPubkey, String deviceId) {
}
