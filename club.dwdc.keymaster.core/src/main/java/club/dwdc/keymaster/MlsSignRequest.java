package club.dwdc.keymaster;

public record MlsSignRequest(byte[] mlsPubkey, byte[] data) {
}
