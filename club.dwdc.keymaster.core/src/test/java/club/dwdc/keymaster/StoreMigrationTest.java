package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Alg;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** Mission 48.3 step 4: the 0.8.x → 0.9.0 rewrite of stored entries. */
class StoreMigrationTest {

    private static final int ALICE = 1955269225;
    private static final long NOW = 1_800_000_000L;

    private static HDPath path(int coin, int use) {
        return HDPath.m(new ChildNumber(44, true), new ChildNumber(coin, true),
                new ChildNumber(ALICE, true), new ChildNumber(use, true), new ChildNumber(0, true));
    }

    private static String pathString(HDPath p) {
        return StoreMigration.pathString(p);
    }

    private static String certBase64() throws Exception {
        try (InputStream in = StoreMigrationTest.class.getResourceAsStream("/x509/tls-client-ok.pem")) {
            String pem = new String(in.readAllBytes());
            String body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
            return Base64.getEncoder().encodeToString(Base64.getDecoder().decode(body));
        }
    }

    /** The shapes a 0.8.1 desktop store holds, for Alice. */
    private static List<KeyEntry> legacyStore(String cert) {
        return List.of(
                new KeyEntry(path(1238, 0x10000), Map.of("comment", "alice@atlanta.com")),
                new KeyEntry(path(1239, 0x10000), Map.of("identity", "alice@atlanta.com",
                        "label", "alice@atlanta.com / certification", "creation_time", "1751234567",
                        "pgp_name", "Alice", "pgp_email", "alice@atlanta.com", "key_type", "ed25519")),
                new KeyEntry(path(1239, 0x10001), Map.of("identity", "alice@atlanta.com",
                        "label", "alice@atlanta.com / signing", "creation_time", "1751234567")),
                new KeyEntry(path(1237, 0), Map.of("identity", "alice@atlanta.com")),
                new KeyEntry(path(1242, 0x10000), Map.of("identity", "alice@atlanta.com")),
                new KeyEntry(path(1240, 0x30102), Map.of("identity", "alice@atlanta.com", X509CertSlot.KEY, cert)));
    }

    @Test
    void everyPathMovesPerTheTable() throws Exception {
        StoreMigration.Result r = StoreMigration.migrate(legacyStore(certBase64()), NOW);
        List<String> paths = r.entries().stream().map(e -> pathString(e.path())).toList();
        assertEquals(List.of(
                "m/44'/1238'/1955269225'/0'/0'",
                "m/44'/1239'/1955269225'/0'/0'",
                "m/44'/1239'/1955269225'/1'/0'",
                "m/44'/1237'/1955269225'/0'/0'",
                "m/44'/1242'/1955269225'/0'/0'",
                "m/44'/1240'/1955269225'/2'/0'"), paths);
        // Each new path is exactly what IdentityPaths builds today.
        Identity alice = new Identity("alice@atlanta.com");
        assertEquals(IdentityPaths.hdPath(IdentityPaths.ssh(alice)), r.entries().get(0).path());
        assertEquals(IdentityPaths.hdPath(IdentityPaths.gpg(alice, 0)), r.entries().get(1).path());
        assertEquals(IdentityPaths.hdPath(IdentityPaths.gpg(alice, 1)), r.entries().get(2).path());
        assertEquals(IdentityPaths.hdPath(IdentityPaths.nostr(alice)), r.entries().get(3).path());
        assertEquals(IdentityPaths.hdPath(IdentityPaths.mlsSign(alice)), r.entries().get(4).path());
        assertEquals(IdentityPaths.hdPath(IdentityPaths.x509(alice, X509Role.TLS_CLIENT)), r.entries().get(5).path());
    }

    @Test
    void algIsRecordedFromTheOldAlgorithmBits() throws Exception {
        List<Alg> algs = StoreMigration.migrate(legacyStore(certBase64()), NOW).entries().stream()
                .map(KeyEntry::alg).toList();
        assertEquals(List.of(Alg.ED25519, Alg.ED25519, Alg.ED25519, Alg.SECP256K1, Alg.ED25519, Alg.P256), algs);
        for (KeyEntry e : StoreMigration.migrate(legacyStore(certBase64()), NOW).entries()) {
            assertNotNull(e.metadata().get(KeyEntry.ALG), "alg recorded explicitly");
        }
    }

    @Test
    void metadataIsKeptExceptCertificateAndCreationTime() throws Exception {
        List<KeyEntry> out = StoreMigration.migrate(legacyStore(certBase64()), NOW).entries();
        assertEquals("alice@atlanta.com", out.get(0).metadata().get("comment"));
        KeyEntry cert = out.get(1);
        assertEquals("Alice", cert.metadata().get("pgp_name"));
        assertEquals("alice@atlanta.com", cert.metadata().get("pgp_email"));
        assertEquals("alice@atlanta.com / certification", cert.metadata().get("label"));
        assertEquals(String.valueOf(NOW), cert.metadata().get("creation_time"), "reset to the migration time");
        assertEquals(String.valueOf(NOW), out.get(2).metadata().get("creation_time"));
        assertNull(out.get(5).metadata().get(X509CertSlot.KEY), "certificate slot dropped");
        assertEquals("alice@atlanta.com", out.get(5).metadata().get("identity"));
    }

    @Test
    void logHasOneLinePerEntryAndNamesTheDroppedCertificate() throws Exception {
        StoreMigration.Result r = StoreMigration.migrate(legacyStore(certBase64()), NOW);
        assertEquals(6, r.log().size());
        assertTrue(r.log().get(0).startsWith("moved m/44'/1238'/1955269225'/65536'/0' -> m/44'/1238'/1955269225'/0'/0'"), r.log().get(0));
        assertTrue(r.log().get(3).startsWith("kept path m/44'/1237'"), r.log().get(3));
        String x509 = r.log().get(5);
        assertTrue(x509.contains("dropped certificate subject=\"CN=alice@atlanta.com\""), x509);
        assertTrue(x509.contains("issuer=\"CN=KeyMaster test CA\""), x509);
    }

    @Test
    void unknownEntriesAreKept() {
        HDPath bitcoin = HDPath.m(new ChildNumber(84, true), new ChildNumber(0, true),
                new ChildNumber(0, true), new ChildNumber(0, false), new ChildNumber(0, false));
        KeyEntry rsa = new KeyEntry(path(1238, 0x21000), Map.of("comment", "rsa"));
        KeyEntry other = new KeyEntry(bitcoin, Map.of());
        StoreMigration.Result r = StoreMigration.migrate(List.of(rsa, other), NOW);
        assertEquals(rsa.path(), r.entries().get(0).path());
        assertEquals(other.path(), r.entries().get(1).path());
        assertTrue(r.log().get(0).startsWith("kept"), r.log().get(0));
    }

    @Test
    void migratedStoreMigratesToItself() throws Exception {
        List<KeyEntry> once = StoreMigration.migrate(legacyStore(certBase64()), NOW).entries();
        List<KeyEntry> twice = StoreMigration.migrate(once, NOW + 5).entries();
        assertEquals(once.stream().map(KeyEntry::path).toList(), twice.stream().map(KeyEntry::path).toList());
    }

    @Test
    void collisionIsRefused() {
        KeyEntry old = new KeyEntry(path(1238, 0x10000), Map.of());
        KeyEntry already = new KeyEntry(path(1238, 0), Map.of());
        assertThrows(IllegalStateException.class, () -> StoreMigration.migrate(List.of(old, already), NOW));
    }
}
