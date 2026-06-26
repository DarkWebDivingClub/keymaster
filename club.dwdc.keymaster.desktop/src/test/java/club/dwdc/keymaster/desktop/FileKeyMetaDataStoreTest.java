package club.dwdc.keymaster.desktop;

import club.dwdc.keymaster.KeyEntry;
import club.dwdc.keyvault.core.AlgField;
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
            new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
            new ChildNumber(0, true)
        );
    }

    static HDPath gpgPath(String identity) {
        return HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.OPENPGP.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
            new ChildNumber(0, true)
        );
    }

    static HDPath nostrPath(String identity) {
        return HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.NOSTR.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex(), true),
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
}
