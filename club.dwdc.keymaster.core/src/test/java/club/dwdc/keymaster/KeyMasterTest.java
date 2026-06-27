package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.nostr.KeyVaultIdentity;
import nostr.util.NostrUtil;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for KeyMaster and KeyMasterController identity + service operations (no relay needed).
 */
class KeyMasterTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    @Test
    void createIdentityReturnsPubkey() {
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), new InMemoryKeyMetaDataStore());
        KeyMasterController ctrl = new KeyMasterController(km);
        String pubkey = ctrl.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");
        assertNotNull(pubkey);
        assertEquals(64, pubkey.length()); // 32 bytes hex
    }

    @Test
    void deterministicIdentity() {
        KeyMaster km1 = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), new InMemoryKeyMetaDataStore());
        KeyMasterController ctrl1 = new KeyMasterController(km1);
        String pub1 = ctrl1.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");

        KeyMaster km2 = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), new InMemoryKeyMetaDataStore());
        KeyMasterController ctrl2 = new KeyMasterController(km2);
        String pub2 = ctrl2.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");

        assertEquals(pub1, pub2);
    }

    @Test
    void differentIdentitiesDifferentKeys() {
        KeyMaster kmAlice = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), new InMemoryKeyMetaDataStore());
        KeyMasterController ctrlAlice = new KeyMasterController(kmAlice);
        String alicePub = ctrlAlice.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");

        KeyMaster kmBob = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), new InMemoryKeyMetaDataStore());
        KeyMasterController ctrlBob = new KeyMasterController(kmBob);
        String bobPub = ctrlBob.createIdentity("bob@ssh.com", "Bob", "bob@ssh.com");

        assertNotEquals(alicePub, bobPub);
    }

    @Test
    void matchesKeyVaultIdentity() {
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), new InMemoryKeyMetaDataStore());
        KeyMasterController ctrl = new KeyMasterController(km);
        String pubkey = ctrl.createIdentity("alice@atlanta.com", "Alice", "alice@atlanta.com");

        Bip32KeyVault vault = new Bip32KeyVault(TEST_MNEMONIC);
        KeyVaultIdentity kvi = new KeyVaultIdentity(vault, "alice@atlanta.com");
        String expected = NostrUtil.bytesToHex(kvi.getPublicKey().getRawData());

        assertEquals(expected, pubkey);
    }

    // ── ApprovalHandler tests ──────────────────────────────────────────

    @Test
    void approvalHandlerAcceptsNull() {
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), new InMemoryKeyMetaDataStore());
        KeyMasterController ctrl = new KeyMasterController(km);
        ctrl.setApprovalHandler(null); // should not throw
        assertNotNull(ctrl);
    }

    @Test
    void approvalHandlerAcceptsLambda() {
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), new InMemoryKeyMetaDataStore());
        KeyMasterController ctrl = new KeyMasterController(km);
        ctrl.setApprovalHandler((type, detail) -> true); // auto-approve lambda
        assertNotNull(ctrl);
    }

    // ── AvatarDescriptor tests ──────────────────────────────────────────

    @Test
    void avatarDescriptorFromJsonWithLoginXpub() {
        String json = """
                {
                  "relay": "ws://localhost:7777",
                  "login_xpub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                  "services": ["ssh", "nostr"]
                }
                """;
        AvatarDescriptor d = AvatarDescriptor.fromJson(json);
        assertEquals("ws://localhost:7777", d.relay());
        assertTrue(d.loginXpub().startsWith("xpub"));
        assertEquals(List.of("ssh", "nostr"), d.services());
    }

    @Test
    void avatarDescriptorFromJsonWithLegacyPubkey() {
        // Backwards compatibility: "pubkey" field still works
        String json = """
                {
                  "relay": "ws://localhost:7777",
                  "pubkey": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
                  "services": ["ssh"]
                }
                """;
        AvatarDescriptor d = AvatarDescriptor.fromJson(json);
        assertTrue(d.loginXpub().startsWith("xpub"));
    }

    @Test
    void avatarDescriptorLoginPubkey() {
        // Use a known xpub and verify loginPubkey() returns a valid 64-char hex
        String json = """
                {
                  "relay": "ws://localhost:7777",
                  "login_xpub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
                }
                """;
        AvatarDescriptor d = AvatarDescriptor.fromJson(json);
        String pubkey = d.loginPubkey();
        assertNotNull(pubkey);
        assertEquals(64, pubkey.length());
        // Should be valid hex
        assertDoesNotThrow(() -> NostrUtil.hexToBytes(pubkey));
    }

    @Test
    void avatarDescriptorRejectsNullRelay() {
        assertThrows(IllegalArgumentException.class, () ->
                new AvatarDescriptor(null, "xpub123", List.of()));
    }

    @Test
    void avatarDescriptorRejectsNullLoginXpub() {
        assertThrows(IllegalArgumentException.class, () ->
                new AvatarDescriptor("ws://localhost:7777", null, List.of()));
    }

    @Test
    void avatarDescriptorDefaultsServicesToEmptyList() {
        String json = """
                {
                  "relay": "ws://localhost:7777",
                  "login_xpub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
                }
                """;
        AvatarDescriptor d = AvatarDescriptor.fromJson(json);
        assertEquals(List.of(), d.services());
    }

    @Test
    void xpubToPubkeyProduces64CharHex() {
        // Use a valid xpub (m/0 from well-known seed)
        byte[] seed = new byte[64];
        seed[0] = 1;
        Bip32KeyDerivator kd = new Bip32KeyDerivator(seed);
        String xpub = kd.deriveXpub(0);
        String pubkey = NostrTransport.xpubToPubkey(xpub);
        assertEquals(64, pubkey.length());
    }

    @Test
    void sshAuthorizedKeysLine() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        String line = SshServiceHandler.getAuthorizedKeysLine(vault, "alice@atlanta.com");
        assertTrue(line.startsWith("ssh-ed25519 "));
        assertTrue(line.endsWith(" alice@atlanta.com"));
    }

    @Test
    void deriveServicePubkeyFromXpubConsistency() {
        byte[] seed = new byte[64];
        seed[0] = 1;
        Bip32KeyDerivator kd = new Bip32KeyDerivator(seed);

        // Derive privkey path: 0 / mangle("ssh") / 0
        int protocolIdx = Bip32KeyDerivator.mangle("ssh");
        byte[] privKey = kd.derive(0, protocolIdx, 0);
        byte[] pubKeyFromPriv = NostrTransport.computeSchnorrPubKey(privKey);
        String pubHexFromPriv = NostrUtil.bytesToHex(pubKeyFromPriv);

        // Derive xpub at m/0, then public-only derive to mangle("ssh")/0
        String xpub = kd.deriveXpub(0);
        String pubHexFromXpub = NostrTransport.deriveServicePubkeyFromXpub(xpub, protocolIdx, 0);

        assertEquals(pubHexFromPriv, pubHexFromXpub,
                "Private-derived pubkey must match public-derived pubkey");
    }
}
