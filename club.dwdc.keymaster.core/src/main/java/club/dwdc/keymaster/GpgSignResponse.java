package club.dwdc.keymaster;

/**
 * A GPG signing response: the raw Ed25519 signature bytes.
 */
public record GpgSignResponse(byte[] signature) {
}
