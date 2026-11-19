package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Alg;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.VaultResult;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Checks that an X.509 certificate belongs to a KeyMaster key. Checks only;
 * nothing here (or anywhere in main code) builds a certificate.
 *
 * <p>Two checks, both required:
 * <ol>
 *   <li><b>Key.</b> The certificate's SubjectPublicKeyInfo must equal, as exact
 *       DER bytes, the SPKI of the vault's P-256 key at
 *       {@link IdentityPaths#x509(Identity, X509Role)}: named curve
 *       prime256v1, uncompressed point. A certificate carrying the right key
 *       as a compressed point or with explicit curve parameters is therefore
 *       rejected — on purpose.</li>
 *   <li><b>Extended Key Usage.</b> Absent: accepted. Exactly the role's
 *       {@link X509Role#ekuOid()}: accepted. Anything else — another usage,
 *       an extra usage (e.g. clientAuth + emailProtection),
 *       anyExtendedKeyUsage, any EKU on a CA — rejected. A present but empty
 *       EKU is malformed.</li>
 * </ol>
 *
 * <p>Not checked: chain, issuer, validity dates, revocation, subject, SAN.
 *
 * <p>Parsing uses the JDK's own {@code SUN} provider by name. BouncyCastle is
 * inserted at provider position 1 elsewhere in KeyMaster, and an unnamed
 * {@code getInstance("X.509")} would silently hand parsing to it.
 */
public final class X509CertCheck {

    /** Result of {@link #check}. */
    public enum Verdict { ACCEPTED, MALFORMED, KEY_MISMATCH, EKU_MISMATCH }

    /**
     * DER SPKI header for an EC P-256 key with a 65-byte uncompressed point.
     * Not java.util.HexFormat: Android has it only from API 34, and the app
     * runs on API 26 and up.
     */
    private static final byte[] P256_SPKI_PREFIX = parseHex(
            "3059301306072a8648ce3d020106082a8648ce3d030107034200");

    private static final int POINT_LENGTH = 65;

    /** Lower- or upper-case hex to bytes. Even length required. */
    private static byte[] parseHex(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("odd hex length: " + hex.length());
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("not hex at " + (2 * i));
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private X509CertCheck() {
    }

    /**
     * Check a certificate against the vault key for this identity and role.
     *
     * @param cert certificate, DER (PEM is also accepted by the parser)
     */
    public static Verdict check(KeyVault vault, Identity identity, X509Role role, byte[] cert) {
        X509Certificate x509;
        List<String> eku;
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509", "SUN");
            x509 = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(cert));
            eku = x509.getExtendedKeyUsage();
        } catch (GeneralSecurityException e) {
            // CertificateException, CertificateParsingException, NoSuchProviderException
            return Verdict.MALFORMED;
        }

        byte[] expected = expectedSpki(vaultPoint(vault, identity, role));
        if (!Arrays.equals(x509.getPublicKey().getEncoded(), expected)) {
            return Verdict.KEY_MISMATCH;
        }
        return checkEku(eku, role);
    }

    /** The SPKI the certificate must carry: fixed P-256 header + the point. */
    static byte[] expectedSpki(byte[] point) {
        byte[] spki = Arrays.copyOf(P256_SPKI_PREFIX, P256_SPKI_PREFIX.length + POINT_LENGTH);
        System.arraycopy(point, 0, spki, P256_SPKI_PREFIX.length, POINT_LENGTH);
        return spki;
    }

    /** The EKU rule alone; {@code eku} is {@code getExtendedKeyUsage()}, may be null. */
    static Verdict checkEku(List<String> eku, X509Role role) {
        if (eku == null) {
            return Verdict.ACCEPTED;
        }
        if (eku.isEmpty()) {
            return Verdict.MALFORMED;
        }
        if (role.ekuOid() != null && eku.equals(List.of(role.ekuOid()))) {
            return Verdict.ACCEPTED;
        }
        return Verdict.EKU_MISMATCH;
    }

    /** The vault's 65-byte SEC1 uncompressed point (04||X||Y) at the role's path. */
    static byte[] vaultPoint(KeyVault vault, Identity identity, X509Role role) {
        VaultResult result = vault.execute(Alg.P256, KeyVault.FN_GET_PUBLIC_KEY, KeyVault.OPT_DEFAULT, null,
                IdentityPaths.x509(identity, role));
        byte[] data = result.isOk() ? result.data() : null;
        // data() is the 65-byte uncompressed point; the chain code is a separate field.
        if (data == null || data.length < POINT_LENGTH || data[0] != 0x04) {
            throw new IllegalStateException("vault returned no uncompressed P-256 point");
        }
        return Arrays.copyOf(data, POINT_LENGTH);
    }
}
