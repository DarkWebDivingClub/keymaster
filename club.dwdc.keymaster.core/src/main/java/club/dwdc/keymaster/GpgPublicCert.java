package club.dwdc.keymaster;

/**
 * A GPG public certificate export: the ASCII-armored OpenPGP public key.
 */
public record GpgPublicCert(String publicCertArmor) {
}
