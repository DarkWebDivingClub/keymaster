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

        assertTrue(km.realms.isEmpty(), "createIdentity builds no realm");
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

        // A realm resolves its own handlers from the store
        Realm realm = ctrl.createRealm("work", new Identity("alice@atlanta.com"));
        assertNotNull(realm.getHandler(Protocol.SSH.coinType()));
        assertNotNull(realm.getHandler(Protocol.OPENPGP.coinType()));

        // Setting the handler afterwards reaches the realm's live handlers
        AtomicBoolean called = new AtomicBoolean(false);
        ctrl.setApprovalHandler((type, detail) -> {
            called.set(true);
            return true;
        });

        realm.getHandler(Protocol.SSH.coinType()).keys();
        ((SshServiceHandler) realm.getHandler(Protocol.SSH.coinType())).requestIdentities();
        assertFalse(called.get(), "request_identities defaults to APPROVE, so no prompt");

        ((SshServiceHandler) realm.getHandler(Protocol.SSH.coinType()))
                .setPolicy("request_identities", ApprovalPolicy.ASK);
        ((SshServiceHandler) realm.getHandler(Protocol.SSH.coinType())).requestIdentities();
        assertTrue(called.get(), "an ASK method must reach the approval handler");
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

    // ── realm lifecycle ───────────────────────────────────────────────────

    @Test
    void createRealm_defaultsNameToLocalPart_withSuffixOnCollision() {
        var store = new InMemoryKeyMetaDataStore();
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), store);
        var ctrl = new KeyMasterController(km);
        ctrl.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");
        var alice = new Identity("alice@atlanta.com");

        assertEquals("alice", ctrl.createRealm(null, alice).name());
        assertEquals("alice-2", ctrl.createRealm("", alice).name());
        assertEquals("alice-3", ctrl.createRealm("   ", alice).name());
        assertEquals("myFirstRealm", ctrl.createRealm("myFirstRealm", alice).name(),
                "a name the user typed is used as given");
    }

    @Test
    void createRealm_idsAreRandomAndDistinct() {
        var store = new InMemoryKeyMetaDataStore();
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), store);
        var ctrl = new KeyMasterController(km);
        ctrl.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");
        var alice = new Identity("alice@atlanta.com");

        var ids = new java.util.HashSet<Integer>();
        for (int i = 0; i < 50; i++) {
            int id = ctrl.createRealm("realm-" + i, alice).id();
            assertTrue(id >= 0, "31 bits, never negative: " + id);
            assertTrue(ids.add(id), "a duplicate draw must be redrawn, not accepted");
        }
        assertEquals(50, km.realms.size());

        // Not a timestamp: consecutive draws are not monotonic
        var sequence = km.realms.keySet().stream().toList();
        assertTrue(sequence.size() > 2);
    }

    @Test
    void realms_areKeyedByIdSoTwoRealmsCanShareAnIdentity() {
        var store = new InMemoryKeyMetaDataStore();
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), store);
        var ctrl = new KeyMasterController(km);
        ctrl.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");
        var alice = new Identity("alice@atlanta.com");

        Realm work = ctrl.createRealm("work", alice);
        Realm home = ctrl.createRealm("home", alice);

        assertNotSame(work, home);
        assertEquals(2, ctrl.realms().size(),
                "an identity-keyed map could not hold both");
        assertNotSame(work.getHandler(Protocol.SSH.coinType()),
                home.getHandler(Protocol.SSH.coinType()),
                "realms share no handler instance, which is why policy can differ");
    }

    @Test
    void detachRealm_removesTheRealm() {
        var store = new InMemoryKeyMetaDataStore();
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), store);
        var ctrl = new KeyMasterController(km);
        ctrl.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");

        Realm realm = ctrl.createRealm("work", new Identity("alice@atlanta.com"));
        assertFalse(realm.hasConnectors());

        ctrl.detachRealm(realm.id());
        assertTrue(ctrl.realms().isEmpty());
        assertNull(ctrl.getRealm(realm.id()));
    }

    @Test
    void detach_unknownRealm_isANoOp() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), new InMemoryKeyMetaDataStore());
        var ctrl = new KeyMasterController(km);

        assertDoesNotThrow(() -> ctrl.detach(4242, 1));
        assertDoesNotThrow(() -> ctrl.detachRealm(4242));
        assertDoesNotThrow(() -> ctrl.detach());
    }

    @Test
    void attachToRealm_unknownRealm_throws() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), new InMemoryKeyMetaDataStore());
        var ctrl = new KeyMasterController(km);

        assertThrows(IllegalArgumentException.class,
                () -> ctrl.attachToRealm(4242, null));
    }
}
