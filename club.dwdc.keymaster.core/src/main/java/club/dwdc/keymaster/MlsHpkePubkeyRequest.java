package club.dwdc.keymaster;

public record MlsHpkePubkeyRequest(byte[] mlsPubkey, int keyType, int index) {
}
