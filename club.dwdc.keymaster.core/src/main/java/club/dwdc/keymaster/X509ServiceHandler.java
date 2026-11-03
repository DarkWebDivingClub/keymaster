package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.VaultResult;
import org.bitcoinj.crypto.HDPath;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Service handler for the {@code "x509"} channel: {@code x509.list},
 * {@code x509.sign} and {@code x509.import}. The JSON shapes are the contract
 * the PKCS#11 module reads; see {@code doc/x509.md}.
 *
 * <p>Keys are <b>computed</b>, not read from the store: one per served
 * identity and {@link X509Role#TEMPLATE} role, at
 * {@link IdentityPaths#x509}. They become this handler's immutable
 * {@link #keys()}, the enforcement boundary. The store is used only for the
 * certificate slot ({@link X509CertSlot}) and is read on every call — no
 * cache. A {@code null} store (Android, until 37.2) lists keys without
 * certificates and refuses imports with {@code "unsupported"}.
 */
public class X509ServiceHandler extends AbstractServiceHandler {

    /** One served key: who, which role, and its path in both forms. */
    private record Slot(Identity identity, X509Role role, int[] path, String pathString) {
        HDPath hdPath() {
            return IdentityPaths.hdPath(path);
        }

        String label() {
            return IdentityPaths.x509Label(identity, role);
        }
    }

    private final List<Slot> slots;
    private final KeyMetaDataStore store;

    /**
     * @param identities the identities this realm serves X.509 for
     * @param store      metadata store holding certificate slots, or {@code null}
     */
    public X509ServiceHandler(KeyVault vault, List<Identity> identities, KeyMetaDataStore store) {
        super(vault, entriesFor(identities));
        this.slots = slotsFor(identities);
        this.store = store;
    }

    // ── methods ───────────────────────────────────────────────────────────

    @ServiceMethod(value = "list", defaultPolicy = ApprovalPolicy.APPROVE)
    public X509ListResponse list() {
        checkApproval("list", "X.509 key listing");
        List<X509Key> keys = new ArrayList<>();
        for (Slot slot : slots) {
            byte[] point = X509CertCheck.vaultPoint(vault, slot.identity(), slot.role());
            byte[] id = sha256(X509CertCheck.expectedSpki(point));
            keys.add(new X509Key(slot.label(), slot.pathString(), point, id, storedCert(slot)));
        }
        return new X509ListResponse(keys);
    }

    /**
     * Sign a 32-byte digest with the key at exactly {@code request.path()}.
     * Inputs are checked before the user is asked, so a malformed request
     * never raises a prompt.
     *
     * @throws IllegalArgumentException {@code "unknown-path"} or {@code "invalid-digest"}
     */
    @ServiceMethod(value = "sign", defaultPolicy = ApprovalPolicy.ASK)
    public X509SignResponse sign(X509SignRequest request) {
        Slot slot = slotFor(request.path());
        if (slot == null) {
            throw new IllegalArgumentException("unknown-path");
        }
        if (request.digest() == null || request.digest().length != 32) {
            throw new IllegalArgumentException("invalid-digest");
        }
        checkApproval("sign", "X.509 signing request: " + slot.label());

        VaultResult result = vault.execute(KeyVault.FN_SIGN, request.digest(), slot.path());
        if (!result.isOk()) {
            throw new IllegalStateException("sign failed: status=" + result.status());
        }
        return new X509SignResponse(result.data());
    }

    /**
     * Check a certificate against the served keys and, if accepted, store it
     * in the matching key's slot, replacing any previous certificate.
     *
     * <p>The certificate's key is matched by SPKI: {@link X509CertCheck}
     * answers {@code KEY_MISMATCH} for every key but the one it carries. No
     * matching key at all is {@code KEY_MISMATCH}. Every verdict is a result.
     *
     * @throws IllegalArgumentException {@code "unsupported"} without a store
     */
    @ServiceMethod(value = "import", defaultPolicy = ApprovalPolicy.ASK)
    public X509ImportResponse importCert(X509ImportRequest request) {
        if (store == null) {
            throw new IllegalArgumentException("unsupported");
        }
        checkApproval("import", "X.509 certificate import");

        byte[] der = request.der();
        if (der == null) {
            return new X509ImportResponse(X509CertCheck.Verdict.MALFORMED, false);
        }
        for (Slot slot : slots) {
            X509CertCheck.Verdict verdict = X509CertCheck.check(vault, slot.identity(), slot.role(), der);
            if (verdict == X509CertCheck.Verdict.MALFORMED) {
                // Parsing comes first in check(), so this holds for every key.
                return new X509ImportResponse(verdict, false);
            }
            if (verdict == X509CertCheck.Verdict.KEY_MISMATCH) {
                continue;
            }
            // This slot's key is the certificate's key.
            if (verdict != X509CertCheck.Verdict.ACCEPTED) {
                return new X509ImportResponse(verdict, false);
            }
            store(slot, canonicalDer(der));
            return new X509ImportResponse(verdict, true);
        }
        return new X509ImportResponse(X509CertCheck.Verdict.KEY_MISMATCH, false);
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private Slot slotFor(String path) {
        for (Slot slot : slots) {
            if (slot.pathString().equals(path)) {
                return slot;
            }
        }
        return null;
    }

    private byte[] storedCert(Slot slot) {
        if (store == null) {
            return null;
        }
        KeyEntry entry = store.getKey(slot.hdPath());
        return entry == null ? null : X509CertSlot.get(entry).orElse(null);
    }

    /** Write the slot: keep the entry's other metadata, replace the certificate. */
    private void store(Slot slot, byte[] der) {
        KeyEntry base = store.getKey(slot.hdPath());
        if (base == null) {
            base = new KeyEntry(slot.hdPath(), Map.of("identity", slot.identity().name()));
        }
        store.addKey(X509CertSlot.with(base, der));
    }

    /** The certificate re-encoded by the SUN parser: DER even if PEM was sent. */
    private static byte[] canonicalDer(byte[] cert) {
        try {
            return CertificateFactory.getInstance("X.509", "SUN")
                    .generateCertificate(new ByteArrayInputStream(cert))
                    .getEncoded();
        } catch (GeneralSecurityException e) {
            // check() already parsed it with the same provider.
            throw new IllegalStateException("certificate re-encoding failed", e);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (GeneralSecurityException e) {
            throw new AssertionError("SHA-256 not available", e);
        }
    }

    private static List<Slot> slotsFor(List<Identity> identities) {
        List<Slot> slots = new ArrayList<>();
        for (Identity identity : identities) {
            for (X509Role role : X509Role.TEMPLATE) {
                int[] path = IdentityPaths.x509(identity, role);
                slots.add(new Slot(identity, role, path, IdentityPaths.pathString(path)));
            }
        }
        return slots;
    }

    /** The served paths as key entries — the base class's {@link #keys()}. */
    private static List<KeyEntry> entriesFor(List<Identity> identities) {
        List<KeyEntry> entries = new ArrayList<>();
        for (Slot slot : slotsFor(identities)) {
            entries.add(new KeyEntry(slot.hdPath(), Map.of("identity", slot.identity().name())));
        }
        return entries;
    }
}
