package club.dwdc.keymaster;

/**
 * Result of {@code x509.import} — a result for every verdict, never an error.
 *
 * @param verdict the {@link X509CertCheck} verdict (wire: the enum name)
 * @param stored  {@code true} only for {@code ACCEPTED}: the certificate was
 *                written to the key's slot, replacing any previous one
 */
public record X509ImportResponse(X509CertCheck.Verdict verdict, boolean stored) {
}
