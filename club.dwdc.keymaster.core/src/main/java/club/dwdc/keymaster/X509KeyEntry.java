package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * X.509 key metadata entry: a P-256 key at {@link IdentityPaths#x509} and, once
 * a CA has issued one and {@code x509.import} has stored it, its certificate.
 *
 * <p>One certificate per key (mission 50). A new import replaces the old one
 * ({@link #withCertificate}); no chain is kept. The role is the path's
 * ({@link #role()}), so it is not stored again.
 */
public class X509KeyEntry extends AbstractKeyEntry {

    private final byte[] certificate;

    /** An entry without a certificate. */
    public X509KeyEntry(HDPath path, String identity) {
        this(path, identity, null);
    }

    /**
     * @param certificate the certificate DER, or {@code null} for none
     */
    public X509KeyEntry(HDPath path, String identity, byte[] certificate) {
        super(path, identity);
        this.certificate = certificate == null ? null : certificate.clone();
    }

    /** The stored certificate DER, or empty if none has been imported. */
    public Optional<byte[]> certificate() {
        return certificate == null ? Optional.empty() : Optional.of(certificate.clone());
    }

    /** A copy of this entry with {@code der} as its certificate, replacing any earlier one. */
    public X509KeyEntry withCertificate(byte[] der) {
        if (der == null) {
            throw new IllegalArgumentException("certificate must not be null");
        }
        return new X509KeyEntry(path(), identity(), der);
    }

    /**
     * The generic form. The certificate goes under {@link X509CertSlot#KEY},
     * the layout {@link KeyMetaDataStore} users read.
     */
    @Override
    public KeyEntry toKeyEntry() {
        Map<String, String> metadata = new HashMap<>();
        metadata.put("identity", identity());
        if (certificate != null) {
            metadata.put(X509CertSlot.KEY, Base64.getEncoder().encodeToString(certificate));
        }
        return new KeyEntry(path(), Map.copyOf(metadata));
    }
}
