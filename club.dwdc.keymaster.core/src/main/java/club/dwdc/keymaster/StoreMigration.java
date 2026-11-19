package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Alg;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.UseField;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * One-time rewrite of stored key entries from keymaster 0.8.x (keyvault 0.5.x)
 * to keymaster 0.9.0 (keyvault 0.6.0), mission 48.3 step 4.
 *
 * <p>For each entry on our {@code m/44'/<coin>'} trees:
 * <ul>
 *   <li>{@code path[3]}: bits 30–16 (the old algorithm) are cleared; for X.509
 *       the variant (the old curve, 1 = P-256) is also set to 0, so it equals
 *       the vault option. The role is kept.</li>
 *   <li>The old algorithm becomes the {@code alg} metadata value
 *       ({@link KeyEntry#ALG}): Schnorr → SECP256K1, Ed25519 → ED25519,
 *       ECDSA variant 1 → P256, ECDSA variant 0 → SECP256K1.</li>
 *   <li>X.509 certificate slots ({@link X509CertSlot#KEY}) are dropped: they
 *       certify a key that no longer exists. Subject and issuer go to the log
 *       so the certificates can be reissued (rollover problem 7).</li>
 *   <li>OpenPGP {@code creation_time} is set to the migration time, so the new
 *       keys are not backdated (48.3 answered question 3).</li>
 * </ul>
 * Entries this migration does not understand (other purposes, RSA, short
 * paths) are kept as they are and logged. Nostr and realm paths keep their
 * value; their keys are unchanged.
 *
 * <p>Pure: no I/O. The store does the backup and the write.
 */
public final class StoreMigration {

    /** Format version written by keymaster 0.9.0. Stores without a version are 0.8.x. */
    public static final int CURRENT_VERSION = 2;

    private static final int OLD_ALG_SCHNORR = 0;
    private static final int OLD_ALG_ED25519 = 1;
    private static final int OLD_ALG_ECDSA = 3;

    private static final Set<Integer> OUR_COINS = Set.of(
            Protocol.NOSTR.coinType(), Protocol.SSH.coinType(), Protocol.OPENPGP.coinType(),
            Protocol.X509.coinType(), Protocol.WIREGUARD.coinType(), Protocol.MLS.coinType());

    /** The migrated entries, in input order, and one log line per input entry. */
    public record Result(List<KeyEntry> entries, List<String> log) {
    }

    private StoreMigration() {
    }

    /**
     * @param entries        the 0.8.x entries
     * @param migrationTime  seconds since the epoch, the new OpenPGP {@code creation_time}
     * @throws IllegalStateException if two entries would land on the same path
     */
    public static Result migrate(List<KeyEntry> entries, long migrationTime) {
        List<KeyEntry> out = new ArrayList<>();
        List<String> log = new ArrayList<>();
        Set<HDPath> seen = new HashSet<>();
        for (KeyEntry entry : entries) {
            KeyEntry migrated = migrateOne(entry, migrationTime, log);
            if (!seen.add(migrated.path())) {
                throw new IllegalStateException("migration collision at " + pathString(migrated.path()));
            }
            out.add(migrated);
        }
        return new Result(List.copyOf(out), List.copyOf(log));
    }

    private static KeyEntry migrateOne(KeyEntry entry, long migrationTime, List<String> log) {
        HDPath path = entry.path();
        String from = pathString(path);
        if (path.size() != 5 || path.get(0).num() != 44 || !path.get(0).isHardened()
                || !OUR_COINS.contains(path.get(1).num())) {
            log.add("kept " + from + " (not a KeyMaster identity path)");
            return entry;
        }

        if (entry.metadata() != null && entry.metadata().containsKey(KeyEntry.ALG)) {
            log.add("kept " + from + " (already migrated, alg=" + entry.metadata().get(KeyEntry.ALG) + ")");
            return entry;
        }

        int coin = path.get(1).num();
        int use = path.get(3).num();
        int oldAlg = UseField.reservedBits(use);
        int variant = UseField.variantOf(use);
        int role = UseField.roleOf(use);

        Alg alg = switch (oldAlg) {
            case OLD_ALG_SCHNORR -> Alg.SECP256K1;
            case OLD_ALG_ED25519 -> Alg.ED25519;
            case OLD_ALG_ECDSA -> variant == 1 ? Alg.P256 : variant == 0 ? Alg.SECP256K1 : null;
            default -> null;
        };
        if (alg == null) {
            log.add("kept " + from + " (algorithm " + oldAlg + " variant " + variant + " not supported by keyvault 0.6.0)");
            return entry;
        }

        int newVariant = coin == Protocol.X509.coinType() ? 0 : variant;
        int newUse = new UseField(newVariant, role).toIndex();
        List<ChildNumber> levels = new ArrayList<>(path.list());
        levels.set(3, new ChildNumber(newUse, path.get(3).isHardened()));
        HDPath newPath = HDPath.m(levels.toArray(new ChildNumber[0]));

        Map<String, String> metadata = new LinkedHashMap<>(entry.metadata() == null ? Map.of() : entry.metadata());
        metadata.put(KeyEntry.ALG, alg.name());

        StringBuilder line = new StringBuilder();
        line.append(from.equals(pathString(newPath)) ? "kept path " : "moved ")
                .append(from);
        if (!from.equals(pathString(newPath))) {
            line.append(" -> ").append(pathString(newPath));
        }
        line.append(" alg=").append(alg.name());

        if (coin == Protocol.X509.coinType() && metadata.containsKey(X509CertSlot.KEY)) {
            line.append("; dropped certificate ").append(describeCertificate(metadata.remove(X509CertSlot.KEY)));
        }
        if (coin == Protocol.OPENPGP.coinType() && metadata.containsKey("creation_time")) {
            line.append("; creation_time ").append(metadata.get("creation_time")).append(" -> ").append(migrationTime);
            metadata.put("creation_time", String.valueOf(migrationTime));
        }
        log.add(line.toString());
        return new KeyEntry(newPath, Map.copyOf(metadata));
    }

    private static String describeCertificate(String base64Der) {
        try {
            byte[] der = Base64.getDecoder().decode(base64Der);
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            return "subject=\"" + cert.getSubjectX500Principal().getName()
                    + "\" issuer=\"" + cert.getIssuerX500Principal().getName()
                    + "\" serial=" + cert.getSerialNumber().toString(16);
        } catch (Exception e) {
            return "(unreadable: " + e.getClass().getSimpleName() + ")";
        }
    }

    /** {@code m/44'/1238'/…} as the metadata store writes it. */
    static String pathString(HDPath path) {
        StringBuilder sb = new StringBuilder("m");
        for (ChildNumber c : path.list()) {
            sb.append('/').append(c.num());
            if (c.isHardened()) {
                sb.append('\'');
            }
        }
        return sb.toString();
    }
}
