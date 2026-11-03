package club.dwdc.keymaster;

/**
 * The X.509 key roles — one table for both the derivation path and the label.
 *
 * <p>{@link #number()} is the role byte of the path's {@code AlgField}, so it
 * is part of a frozen identity path ({@link IdentityPaths#x509}) and
 * <b>can never change</b>. {@link #token()} is the suffix of the generated
 * label ({@link IdentityPaths#x509Label}); changing it changes every label of
 * that role, so treat it as frozen too. Tokens use only RFC 3986 unreserved
 * characters, so they pass through a PKCS#11 URI unencoded.
 *
 * <p>{@link #ekuOid()} is the one Extended Key Usage a certificate for this
 * role may carry ({@link X509CertCheck}). A CA has none: any EKU on a CA
 * certificate is rejected.
 */
public enum X509Role {

    CA(0, "ca", null),
    TLS_SERVER(1, "tls-server", "1.3.6.1.5.5.7.3.1"),     // serverAuth
    TLS_CLIENT(2, "tls-client", "1.3.6.1.5.5.7.3.2"),     // clientAuth
    CODE_SIGNING(3, "code-signing", "1.3.6.1.5.5.7.3.3"), // codeSigning
    SMIME(4, "smime", "1.3.6.1.5.5.7.3.4");               // emailProtection

    private final int number;
    private final String token;
    private final String ekuOid;

    X509Role(int number, String token, String ekuOid) {
        this.number = number;
        this.token = token;
        this.ekuOid = ekuOid;
    }

    /** The {@code AlgField} role byte. Frozen. */
    public int number() {
        return number;
    }

    /** The label suffix, e.g. {@code "tls-client"}. */
    public String token() {
        return token;
    }

    /** The only EKU OID accepted for this role, or {@code null} for CA. */
    public String ekuOid() {
        return ekuOid;
    }
}
