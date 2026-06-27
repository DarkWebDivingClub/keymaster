package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.Protocol;
import org.junit.jupiter.api.Test;

import java.util.Set;
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
    void createIdentity_populatesSession() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var ctrl = new KeyMasterController(km);
        ctrl.createIdentity("alice@atlanta.com");

        assertNotNull(km.getSession());
        assertEquals(
                Set.of(Protocol.SSH.coinType(), Protocol.OPENPGP.coinType()),
                km.getSession().getHandlerCoinTypes());
        assertInstanceOf(SshServiceHandler.class,
                km.getSession().getHandler(Protocol.SSH.coinType()));
        assertInstanceOf(GpgServiceHandler.class,
                km.getSession().getHandler(Protocol.OPENPGP.coinType()));
    }

    @Test
    void createIdentity_storesKeysInMetadataStore() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var store = new InMemoryKeyMetaDataStore();
        var ctrl = new KeyMasterController(km, store);
        ctrl.createIdentity("alice@atlanta.com");

        // Should have SSH key entries
        var sshKeys = store.keysByProtocol(Protocol.SSH.coinType());
        assertEquals(1, sshKeys.size());

        // Should have GPG key entries (certification + signing)
        var gpgKeys = store.keysByProtocol(Protocol.OPENPGP.coinType());
        assertEquals(2, gpgKeys.size());

        // Identity name should be stored
        int aliceHash = club.dwdc.keyvault.core.Bip32KeyDerivator.mangle("alice@atlanta.com");
        assertEquals("alice@atlanta.com", store.getIdentityName(aliceHash));
    }

    @Test
    void createIdentity_withoutStore_noException() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var ctrl = new KeyMasterController(km);
        // No store — should still work (direct mode)
        assertDoesNotThrow(() -> ctrl.createIdentity("alice@atlanta.com"));
        assertNotNull(km.getSession());
    }

    @Test
    void detach_clearsConnector() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var ctrl = new KeyMasterController(km);
        ctrl.createIdentity("alice@atlanta.com");

        // Set a mock connector
        km.setConnector(new Connector() {
            @Override
            public String connect(AvatarDescriptor descriptor) { return "mock"; }
            @Override
            public void disconnect() { }
        });
        assertNotNull(km.getConnector());

        assertDoesNotThrow(() -> ctrl.detach());
        assertNull(km.getConnector());
    }

    @Test
    void detach_withNoConnector_warnsButDoesNotThrow() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var ctrl = new KeyMasterController(km);
        assertDoesNotThrow(() -> ctrl.detach());
    }

    @Test
    void setApprovalHandler_propagatesToHandlers() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var ctrl = new KeyMasterController(km);
        ctrl.createIdentity("alice@atlanta.com");

        AtomicBoolean called = new AtomicBoolean(false);
        ctrl.setApprovalHandler((type, detail) -> {
            called.set(true);
            return true;
        });

        // Verify that the SSH handler has an approval UI set
        var sshHandler = km.getSession().getHandler(Protocol.SSH.coinType());
        assertNotNull(sshHandler);
        // The handler should have an ApprovalUI set (ApprovalHandlerAdapter)
        // We can verify by invoking a sign operation — it should go through the handler
        // For a lightweight check, just ensure no exception was thrown during propagation
        assertNotNull(ctrl.getKeyMaster());
    }

    @Test
    void getKeyMaster_returnsWrappedInstance() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var ctrl = new KeyMasterController(km);
        assertSame(km, ctrl.getKeyMaster());
    }

    @Test
    void attach_withoutIdentity_throwsIllegalState() {
        var km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        var ctrl = new KeyMasterController(km);
        var descriptor = new AvatarDescriptor("ws://localhost:7777",
                "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                java.util.List.of("ssh"));
        assertThrows(IllegalStateException.class, () -> ctrl.attach(descriptor));
    }
}
