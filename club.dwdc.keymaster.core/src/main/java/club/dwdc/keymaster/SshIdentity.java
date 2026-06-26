package club.dwdc.keymaster;

/**
 * An SSH identity: the SSH wire-format key blob and a human-readable comment.
 */
public record SshIdentity(byte[] keyBlob, String comment) {
}
