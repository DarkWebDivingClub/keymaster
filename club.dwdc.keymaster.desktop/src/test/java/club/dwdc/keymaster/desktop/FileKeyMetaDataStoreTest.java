package club.dwdc.keymaster.desktop;

import club.dwdc.keymaster.Identity;
import club.dwdc.keymaster.IdentityPaths;
import club.dwdc.keymaster.KeyEntry;
import club.dwdc.keymaster.X509CertSlot;
import club.dwdc.keymaster.X509Role;
import club.dwdc.keyvault.core.UseField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Protocol;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class FileKeyMetaDataStoreTest {

    @TempDir Path tempDir;

    static HDPath sshPath(String identity) {
        return HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.SSH.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new UseField(0, 0).toIndex(), true),
            new ChildNumber(0, true)
        );
    }

    static HDPath gpgPath(String identity) {
        return HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.OPENPGP.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new UseField(0, 0).toIndex(), true),
            new ChildNumber(0, true)
        );
    }

    static HDPath nostrPath(String identity) {
        return HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.NOSTR.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new UseField(0, 0).toIndex(), true),
            new ChildNumber(0, true)
        );
    }

    @Test
    void addKeyAndGetRoundTrip() {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        HDPath path = sshPath("alice");
        KeyEntry entry = new KeyEntry(path, Map.of("label", "work key"));

        store.addKey(entry);
        KeyEntry got = store.getKey(path);

        assertNotNull(got);
        assertEquals(path, got.path());
        assertEquals("work key", got.metadata().get("label"));
    }

    @Test
    void addKeyOverwritesSamePath() {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        HDPath path = sshPath("alice");

        store.addKey(new KeyEntry(path, Map.of("label", "old")));
        store.addKey(new KeyEntry(path, Map.of("label", "new")));

        assertEquals(1, store.allKeys().size());
        assertEquals("new", store.getKey(path).metadata().get("label"));
    }

    @Test
    void removeKeyExisting() {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        HDPath path = sshPath("alice");
        store.addKey(new KeyEntry(path, Map.of()));

        store.removeKey(path);
        assertNull(store.getKey(path));
    }

    @Test
    void removeKeyNonExistent() {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        assertDoesNotThrow(() -> store.removeKey(sshPath("nobody")));
    }

    @Test
    void allKeysReturnsAll() {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        store.addKey(new KeyEntry(sshPath("alice"), Map.of()));
        store.addKey(new KeyEntry(sshPath("bob"), Map.of()));
        store.addKey(new KeyEntry(gpgPath("alice"), Map.of()));

        assertEquals(3, store.allKeys().size());
    }

    @Test
    void allKeysEmptyWhenNoFile() {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        assertTrue(store.allKeys().isEmpty());
    }

    @Test
    void keysByProtocolFilters() {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        store.addKey(new KeyEntry(sshPath("alice"), Map.of()));
        store.addKey(new KeyEntry(sshPath("bob"), Map.of()));
        store.addKey(new KeyEntry(gpgPath("alice"), Map.of()));

        List<KeyEntry> sshKeys = store.keysByProtocol(Protocol.SSH.coinType());
        assertEquals(2, sshKeys.size());

        List<KeyEntry> gpgKeys = store.keysByProtocol(Protocol.OPENPGP.coinType());
        assertEquals(1, gpgKeys.size());
    }

    @Test
    void keysByIdentityFilters() {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        store.addKey(new KeyEntry(sshPath("alice"), Map.of()));
        store.addKey(new KeyEntry(gpgPath("alice"), Map.of()));
        store.addKey(new KeyEntry(sshPath("bob"), Map.of()));

        List<KeyEntry> aliceKeys = store.keysByIdentity(Bip32KeyDerivator.mangle("alice"));
        assertEquals(2, aliceKeys.size());

        List<KeyEntry> bobKeys = store.keysByIdentity(Bip32KeyDerivator.mangle("bob"));
        assertEquals(1, bobKeys.size());
    }

    @Test
    void addIdentityAndGetName() {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        store.addIdentity("alice@atlanta.com");

        int hash = Bip32KeyDerivator.mangle("alice@atlanta.com");
        assertEquals("alice@atlanta.com", store.getIdentityName(hash));
    }

    @Test
    void getIdentityNameUnknown() {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        assertNull(store.getIdentityName(999999));
    }

    @Test
    void persistenceSurvivesReload() {
        FileKeyMetaDataStore storeA = new FileKeyMetaDataStore(tempDir);
        HDPath path = sshPath("alice");
        storeA.addKey(new KeyEntry(path, Map.of("label", "persistent")));
        storeA.addIdentity("alice@atlanta.com");

        FileKeyMetaDataStore storeB = new FileKeyMetaDataStore(tempDir);
        assertNotNull(storeB.getKey(path));
        assertEquals("persistent", storeB.getKey(path).metadata().get("label"));
        assertEquals("alice@atlanta.com",
                storeB.getIdentityName(Bip32KeyDerivator.mangle("alice@atlanta.com")));
    }

    @Test
    void pathSerializedAsBip32StringInJson() throws Exception {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        store.addKey(new KeyEntry(sshPath("alice"), Map.of()));

        String json = Files.readString(tempDir.resolve("key-metadata.json"));
        // Path should be serialized as standard BIP-32 string with apostrophe notation
        assertTrue(json.contains("m/44'/"), "path starts with m/44'/ in BIP-32 format");
        assertTrue(json.contains("1238'"), "SSH coin type in path");
    }

    @Test
    void x509CertSurvivesReload() throws Exception {
        HDPath path = IdentityPaths.hdPath(
                IdentityPaths.x509(new Identity("alice@atlanta.com"), X509Role.TLS_CLIENT));
        byte[] der = {0x30, (byte) 0x82, 0x01, 0x00, 0x7F, (byte) 0xFF};

        new FileKeyMetaDataStore(tempDir).addKey(X509CertSlot.with(
                new KeyEntry(path, Map.of("identity", "alice@atlanta.com")), der));

        FileKeyMetaDataStore reloaded = new FileKeyMetaDataStore(tempDir);
        assertArrayEquals(der, X509CertSlot.get(reloaded.getKey(path)).orElseThrow());
        assertTrue(Files.readString(tempDir.resolve("key-metadata.json")).contains("\"x509_cert\""));
    }

    @Test
    void pathStringMatchesWhatTheStoreWrites() throws Exception {
        // x509.sign matches paths by exact string against IdentityPaths.pathString,
        // which must be the form key-metadata.json holds.
        int[] path = IdentityPaths.x509(new Identity("alice@atlanta.com"), X509Role.TLS_CLIENT);
        new FileKeyMetaDataStore(tempDir).addKey(
                new KeyEntry(IdentityPaths.hdPath(path), Map.of("identity", "alice@atlanta.com")));

        String json = Files.readString(tempDir.resolve("key-metadata.json"));
        String expected = "m/44'/1240'/1955269225'/2'/0'";
        assertEquals(expected, IdentityPaths.pathString(path));
        assertTrue(json.contains("\"path\": \"" + expected + "\"")
                        || json.contains("\"path\":\"" + expected + "\""),
                json);

        // And through the adapter directly, for a path with a non-hardened level.
        int[] mixed = {44 | 0x80000000, 7, 0};
        java.io.StringWriter out = new java.io.StringWriter();
        new FileKeyMetaDataStore.HDPathTypeAdapter().write(
                new com.google.gson.stream.JsonWriter(out), IdentityPaths.hdPath(mixed));
        assertEquals("\"" + IdentityPaths.pathString(mixed) + "\"", out.toString());
    }

    @Test
    void filePermissions0600() throws Exception {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        store.addKey(new KeyEntry(sshPath("alice"), Map.of()));

        Path file = tempDir.resolve("key-metadata.json");
        assertTrue(Files.exists(file));
        Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file);
        assertEquals(
                Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                perms);
    }

    @Test
    void multipleProtocolsMultipleIdentities() {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);

        store.addKey(new KeyEntry(sshPath("alice"), Map.of("type", "ssh")));
        store.addKey(new KeyEntry(gpgPath("alice"), Map.of("type", "gpg")));
        store.addKey(new KeyEntry(nostrPath("alice"), Map.of("type", "nostr")));
        store.addKey(new KeyEntry(sshPath("bob"), Map.of("type", "ssh")));
        store.addKey(new KeyEntry(gpgPath("bob"), Map.of("type", "gpg")));

        store.addIdentity("alice");
        store.addIdentity("bob");

        assertEquals(5, store.allKeys().size());
        assertEquals(2, store.keysByProtocol(Protocol.SSH.coinType()).size());
        assertEquals(2, store.keysByProtocol(Protocol.OPENPGP.coinType()).size());
        assertEquals(1, store.keysByProtocol(Protocol.NOSTR.coinType()).size());

        assertEquals(3, store.keysByIdentity(Bip32KeyDerivator.mangle("alice")).size());
        assertEquals(2, store.keysByIdentity(Bip32KeyDerivator.mangle("bob")).size());

        assertEquals("alice", store.getIdentityName(Bip32KeyDerivator.mangle("alice")));
        assertEquals("bob", store.getIdentityName(Bip32KeyDerivator.mangle("bob")));
    }

    // ── Format version and the 0.8.x migration (mission 48.3 step 5) ──

    /** A 0.8.x store: a bare JSON array with the old path values. */
    private static final String LEGACY_STORE = """
            [
              {"path": "m/44'/1238'/1955269225'/65536'/0'", "metadata": {"comment": "alice@atlanta.com"}},
              {"path": "m/44'/1239'/1955269225'/65536'/0'", "metadata": {"identity": "alice@atlanta.com", "creation_time": "1751234567"}},
              {"path": "m/44'/1239'/1955269225'/65537'/0'", "metadata": {"identity": "alice@atlanta.com", "creation_time": "1751234567"}},
              {"path": "m/44'/1237'/1955269225'/0'/0'", "metadata": {"identity": "alice@atlanta.com"}},
              {"path": "m/44'/1240'/1955269225'/2'/0'", "metadata": {"identity": "alice@atlanta.com"}}
            ]
            """;

    @Test
    void legacyStoreIsMigratedOnceWithBackupAndLog() throws Exception {
        Path file = tempDir.resolve("key-metadata.json");
        Files.writeString(file, LEGACY_STORE);

        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);

        Identity alice = new Identity("alice@atlanta.com");
        assertNotNull(store.getKey(IdentityPaths.hdPath(IdentityPaths.ssh(alice))));
        assertNotNull(store.getKey(IdentityPaths.hdPath(IdentityPaths.gpg(alice, 0))));
        assertNotNull(store.getKey(IdentityPaths.hdPath(IdentityPaths.gpg(alice, 1))));
        assertNotNull(store.getKey(IdentityPaths.hdPath(IdentityPaths.nostr(alice))));
        assertNotNull(store.getKey(IdentityPaths.hdPath(IdentityPaths.x509(alice, X509Role.TLS_CLIENT))));
        assertEquals(5, store.allKeys().size());
        assertEquals("alice@atlanta.com",
                store.getKey(IdentityPaths.hdPath(IdentityPaths.ssh(alice))).metadata().get("comment"));

        Path backup = tempDir.resolve("key-metadata.json" + FileKeyMetaDataStore.BACKUP_SUFFIX);
        assertEquals(LEGACY_STORE, Files.readString(backup), "backup is the original, byte for byte");
        String log = Files.readString(tempDir.resolve(FileKeyMetaDataStore.MIGRATION_LOG));
        assertEquals(5, log.lines().filter(l -> !l.startsWith("#")).count(), log);

        String json = Files.readString(file);
        assertTrue(json.contains("\"version\": 2"), json);
        assertFalse(json.contains("65536"), json);
    }

    @Test
    void secondLoadDoesNotMigrateAgain() throws Exception {
        Path file = tempDir.resolve("key-metadata.json");
        Files.writeString(file, LEGACY_STORE);
        new FileKeyMetaDataStore(tempDir);
        String afterFirst = Files.readString(file);
        Path logFile = tempDir.resolve(FileKeyMetaDataStore.MIGRATION_LOG);
        String firstLog = Files.readString(logFile);

        FileKeyMetaDataStore again = new FileKeyMetaDataStore(tempDir);

        assertEquals(5, again.allKeys().size());
        assertEquals(afterFirst, Files.readString(file));
        assertEquals(firstLog, Files.readString(logFile), "no second migration log");
    }

    @Test
    void corruptStoreFailsAndIsLeftUnchanged() throws Exception {
        Path file = tempDir.resolve("key-metadata.json");
        String corrupt = "[ {\"path\": \"m/44'/1238'/1'/65536'/0'\", \"metadata\": ";
        Files.writeString(file, corrupt);

        assertThrows(IllegalStateException.class, () -> new FileKeyMetaDataStore(tempDir));

        assertEquals(corrupt, Files.readString(file));
        assertFalse(Files.exists(tempDir.resolve("key-metadata.json" + FileKeyMetaDataStore.BACKUP_SUFFIX)));
    }

    @Test
    void unreadablePathFailsAndIsLeftUnchanged() throws Exception {
        Path file = tempDir.resolve("key-metadata.json");
        String bad = "[{\"path\": \"not-a-path\", \"metadata\": {}}]";
        Files.writeString(file, bad);
        assertThrows(RuntimeException.class, () -> new FileKeyMetaDataStore(tempDir));
        assertEquals(bad, Files.readString(file));
    }

    @Test
    void newerFormatIsRefused() throws Exception {
        Path file = tempDir.resolve("key-metadata.json");
        String newer = "{\"version\": 3, \"keys\": []}";
        Files.writeString(file, newer);
        assertThrows(IllegalStateException.class, () -> new FileKeyMetaDataStore(tempDir));
        assertEquals(newer, Files.readString(file));
    }

    @Test
    void newStoreIsWrittenInTheCurrentFormat() throws Exception {
        FileKeyMetaDataStore store = new FileKeyMetaDataStore(tempDir);
        store.addKey(new KeyEntry(IdentityPaths.hdPath(IdentityPaths.ssh(new Identity("bob@biloxi.com"))), Map.of()));
        String json = Files.readString(tempDir.resolve("key-metadata.json"));
        assertTrue(json.startsWith("{"), json);
        assertTrue(json.contains("\"version\": 2"), json);
        assertFalse(Files.exists(tempDir.resolve("key-metadata.json" + FileKeyMetaDataStore.BACKUP_SUFFIX)));
    }
}
