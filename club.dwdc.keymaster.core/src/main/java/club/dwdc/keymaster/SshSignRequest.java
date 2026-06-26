package club.dwdc.keymaster;

/**
 * An SSH signing request: identifies the key by blob and provides data to sign.
 */
public record SshSignRequest(byte[] keyBlob, byte[] data) {
}
