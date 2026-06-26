package club.dwdc.keymaster;

/**
 * An SSH signing response: the raw signature bytes and the key type identifier.
 */
public record SshSignResponse(byte[] signature, String keyType) {
}
