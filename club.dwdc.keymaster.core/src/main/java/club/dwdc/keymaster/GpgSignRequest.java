package club.dwdc.keymaster;

/**
 * A GPG signing request: identifies the key by raw public key and provides data to sign.
 */
public record GpgSignRequest(byte[] publicKey, byte[] data) {
}
