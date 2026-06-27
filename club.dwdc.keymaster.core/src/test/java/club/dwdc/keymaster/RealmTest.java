package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.*;

class RealmTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    static KeyEntry sshKeyEntry(String identity) {
        HDPath path = HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.SSH.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
            new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        return new KeyEntry(path, Map.of("comment", identity));
    }

    static KeyEntry gpgKeyEntry(String identity, int role, String roleName) {
        HDPath path = HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.OPENPGP.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, role).toIndex(), true),
            new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        return new KeyEntry(path, Map.of(
                "label", identity + " / " + roleName,
                "key_type", "ed25519",
                "identity", identity,
                "creation_time", "1700000000",
                "pgp_name", identity,
                "pgp_email", identity));
    }

    static void populateStore(InMemoryKeyMetaDataStore store, String identity) {
        store.addIdentity(identity);
        store.addKey(sshKeyEntry(identity));
        store.addKey(gpgKeyEntry(identity, 0, "certification"));
        store.addKey(gpgKeyEntry(identity, 1, "signing"));
    }

    // ── resolveHandlers tests ─────────────────────────────────────────────

    @Test
    void resolveHandlers_singleIdentity_createsBothHandlers() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");

        int aliceHash = Bip32KeyDerivator.mangle("alice@atlanta.com");
        Predicate<KeyEntry> selectAlice = k -> k.identity() == aliceHash;

        var realm = new Realm(List.of(selectAlice), store, vault, null);

        assertNotNull(realm.getHandler(Protocol.SSH.coinType()));
        assertNotNull(realm.getHandler(Protocol.OPENPGP.coinType()));
        assertEquals(
                Set.of(Protocol.SSH.coinType(), Protocol.OPENPGP.coinType()),
                realm.getHandlerCoinTypes());
    }

    @Test
    void resolveHandlers_protocolFilter_onlySshHandler() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");

        // Filter to SSH keys only
        Predicate<KeyEntry> sshOnly = k -> k.coinType() == Protocol.SSH.coinType();

        var realm = new Realm(List.of(sshOnly), store, vault, null);

        assertNotNull(realm.getHandler(Protocol.SSH.coinType()));
        assertNull(realm.getHandler(Protocol.OPENPGP.coinType()));
        assertEquals(Set.of(Protocol.SSH.coinType()), realm.getHandlerCoinTypes());
    }

    @Test
    void resolveHandlers_multipleIdentities_handlersContainKeysFromBoth() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");
        populateStore(store, "bob@ssh.com");

        int aliceHash = Bip32KeyDerivator.mangle("alice@atlanta.com");
        int bobHash = Bip32KeyDerivator.mangle("bob@ssh.com");
        Predicate<KeyEntry> selectAlice = k -> k.identity() == aliceHash;
        Predicate<KeyEntry> selectBob = k -> k.identity() == bobHash;

        var realm = new Realm(List.of(selectAlice, selectBob), store, vault, null);

        assertNotNull(realm.getHandler(Protocol.SSH.coinType()));
        assertNotNull(realm.getHandler(Protocol.OPENPGP.coinType()));
        assertEquals(
                Set.of(Protocol.SSH.coinType(), Protocol.OPENPGP.coinType()),
                realm.getHandlerCoinTypes());
    }

    @Test
    void resolveHandlers_allKeys_allCoinTypesPresent() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");

        Predicate<KeyEntry> all = k -> true;

        var realm = new Realm(List.of(all), store, vault, null);

        assertTrue(realm.getHandlerCoinTypes().contains(Protocol.SSH.coinType()));
        assertTrue(realm.getHandlerCoinTypes().contains(Protocol.OPENPGP.coinType()));
    }

    // ── getHandler tests ──────────────────────────────────────────────────

    @Test
    void getHandler_returnsCorrectHandlerByCoinType() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");

        int aliceHash = Bip32KeyDerivator.mangle("alice@atlanta.com");
        var realm = new Realm(List.of(k -> k.identity() == aliceHash), store, vault, null);

        assertInstanceOf(SshServiceHandler.class, realm.getHandler(Protocol.SSH.coinType()));
        assertInstanceOf(GpgServiceHandler.class, realm.getHandler(Protocol.OPENPGP.coinType()));
    }

    @Test
    void getHandler_returnsNullForUnknownCoinType() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");

        int aliceHash = Bip32KeyDerivator.mangle("alice@atlanta.com");
        var realm = new Realm(List.of(k -> k.identity() == aliceHash), store, vault, null);

        assertNull(realm.getHandler(99999));
    }

    // ── putHandler tests ──────────────────────────────────────────────────

    @Test
    void putHandler_setsHandler() {
        var realm = new Realm();
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new SshServiceHandler(vault, List.of(sshKeyEntry("alice@atlanta.com")));

        realm.putHandler(Protocol.SSH.coinType(), handler);

        assertSame(handler, realm.getHandler(Protocol.SSH.coinType()));
    }

    @Test
    void putHandler_replacesExistingHandler() {
        var realm = new Realm();
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var first = new SshServiceHandler(vault, List.of(sshKeyEntry("alice@atlanta.com")));
        var second = new SshServiceHandler(vault, List.of(sshKeyEntry("bob@ssh.com")));

        realm.putHandler(Protocol.SSH.coinType(), first);
        realm.putHandler(Protocol.SSH.coinType(), second);

        assertSame(second, realm.getHandler(Protocol.SSH.coinType()));
    }

    @Test
    void getHandlerCoinTypes_reflectsPuts() {
        var realm = new Realm();
        var vault = new Bip32KeyVault(TEST_MNEMONIC);

        assertTrue(realm.getHandlerCoinTypes().isEmpty());

        realm.putHandler(Protocol.SSH.coinType(),
                new SshServiceHandler(vault, List.of(sshKeyEntry("alice@atlanta.com"))));
        realm.putHandler(Protocol.OPENPGP.coinType(),
                new GpgServiceHandler(vault, List.of()));

        assertEquals(
                Set.of(Protocol.SSH.coinType(), Protocol.OPENPGP.coinType()),
                realm.getHandlerCoinTypes());
    }
}
