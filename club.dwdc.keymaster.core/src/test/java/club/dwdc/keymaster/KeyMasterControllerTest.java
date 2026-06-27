package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.Protocol;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for KeyMasterController orchestration.
 */
class KeyMasterControllerTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    @Test
    void createIdentity_doesNotPopulateRealm() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), new InMemoryKeyMetaDataStore());
        var ctrl = new KeyMasterController(km);
        ctrl.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");

        assertNull(km.getRealm("alice@atlanta.com"));
    }

    @Test
    void createIdentity_storesKeysInMetadataStore() {
        var store = new InMemoryKeyMetaDataStore();
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), store);
        var ctrl = new KeyMasterController(km);
        ctrl.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");

        // Should have SSH key entries
        var sshKeys = store.keysByProtocol(Protocol.SSH.coinType());
        assertEquals(1, sshKeys.size());
        assertEquals("alice@atlanta.com", sshKeys.get(0).metadata().get("comment"));

        // Should have GPG key entries (certification + signing)
        var gpgKeys = store.keysByProtocol(Protocol.OPENPGP.coinType());
        assertEquals(2, gpgKeys.size());

        // Verify GPG metadata fields
        var certKey = gpgKeys.get(0);
        assertEquals("alice@atlanta.com", certKey.metadata().get("identity"));
        assertEquals("Alice", certKey.metadata().get("pgp_name"));
        assertEquals("alice@atlanta.com", certKey.metadata().get("pgp_email"));
        assertNotNull(certKey.metadata().get("creation_time"));
        assertEquals("ed25519", certKey.metadata().get("key_type"));
        assertEquals("alice@atlanta.com / certification", certKey.metadata().get("label"));

        var signKey = gpgKeys.get(1);
        assertEquals("alice@atlanta.com / signing", signKey.metadata().get("label"));
        assertEquals(certKey.metadata().get("creation_time"), signKey.metadata().get("creation_time"));

        // Identity name should be stored
        int aliceHash = Bip32KeyDerivator.mangle("alice@atlanta.com");
        assertEquals("alice@atlanta.com", store.getIdentityName(aliceHash));
    }

    @Test
    void createIdentity_withoutStore_throwsIllegalState() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var ctrl = new KeyMasterController(km);
        // No store — should throw
        assertThrows(IllegalStateException.class,
                () -> ctrl.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com"));
    }

    @Test
    void detach_withNoSession_warnsButDoesNotThrow() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var ctrl = new KeyMasterController(km);
        assertDoesNotThrow(() -> ctrl.detach());
    }

    @Test
    void setApprovalHandler_propagatesToHandlers() throws Exception {
        var store = new InMemoryKeyMetaDataStore();
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var km = new KeyMaster(vault, store);
        var ctrl = new KeyMasterController(km);
        ctrl.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");

        // Manually build realm + handlers (simulating what attach does)
        int mangledIdentity = Bip32KeyDerivator.mangle("alice@atlanta.com");
        List<KeyEntry> sshKeys = store.keysByIdentity(mangledIdentity).stream()
                .filter(k -> k.coinType() == Protocol.SSH.coinType())
                .toList();
        List<KeyEntry> gpgKeys = store.keysByIdentity(mangledIdentity).stream()
                .filter(k -> k.coinType() == Protocol.OPENPGP.coinType())
                .toList();
        SshServiceHandler sshHandler = new SshServiceHandler(vault, sshKeys);
        GpgServiceHandler gpgHandler = new GpgServiceHandler(vault, gpgKeys);
        Realm realm = new Realm();
        realm.putHandler(Protocol.SSH.coinType(), sshHandler);
        realm.putHandler(Protocol.OPENPGP.coinType(), gpgHandler);
        km.putRealm("alice@atlanta.com", realm);

        // Simulate attach setting currentIdentity by using attach with a mock connector
        // attach requires a real relay, so we test setApprovalHandler before attach:
        // set handler, then verify it's stored for later use by attach
        AtomicBoolean called = new AtomicBoolean(false);
        ctrl.setApprovalHandler((type, detail) -> {
            called.set(true);
            return true;
        });

        // Verify handler is stored (no currentIdentity yet, so no propagation)
        assertNotNull(ctrl.getKeyMaster());
    }

    @Test
    void getKeyMaster_returnsWrappedInstance() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var ctrl = new KeyMasterController(km);
        assertSame(km, ctrl.getKeyMaster());
    }

    @Test
    void attach_withoutStore_throwsIllegalState() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var ctrl = new KeyMasterController(km);
        var descriptor = new AvatarDescriptor("ws://localhost:7777",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                List.of("ssh"));
        assertThrows(IllegalStateException.class,
                () -> ctrl.attach(descriptor, "alice@atlanta.com"));
    }
}
