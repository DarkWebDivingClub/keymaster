package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.nostr.KeyVaultIdentity;
import nostr.util.NostrUtil;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for KeyMaster identity derivation (no relay needed).
 */
class KeyMasterTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    @Test
    void createAndLogin() {
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        km.createIdentity("alice@atlanta.com");
        assertNotNull(km.getPubKeyHex());
        assertEquals(64, km.getPubKeyHex().length()); // 32 bytes hex
    }

    @Test
    void deterministicIdentity() {
        KeyMaster km1 = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        km1.createIdentity("alice@atlanta.com");
        KeyMaster km2 = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        km2.createIdentity("alice@atlanta.com");
        assertEquals(km1.getPubKeyHex(), km2.getPubKeyHex());
    }

    @Test
    void differentIdentitiesDifferentKeys() {
        KeyMaster alice = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        alice.createIdentity("alice@atlanta.com");
        KeyMaster bob = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        bob.createIdentity("bob@ssh.com");
        assertNotEquals(alice.getPubKeyHex(), bob.getPubKeyHex());
    }

    @Test
    void matchesKeyVaultIdentity() {
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC));
        km.createIdentity("alice@atlanta.com");

        Bip32KeyVault vault = new Bip32KeyVault(TEST_MNEMONIC);
        KeyVaultIdentity kvi = new KeyVaultIdentity(vault, "alice@atlanta.com");
        String expected = NostrUtil.bytesToHex(kvi.getPublicKey().getRawData());

        assertEquals(expected, km.getPubKeyHex());
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
    void avatarDescriptorLoginNpub() {
        // Use a known xpub and verify loginNpub() returns a valid 64-char hex
        String json = """
                {
                  "relay": "ws://localhost:7777",
                  "login_xpub": "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
                }
                """;
        AvatarDescriptor d = AvatarDescriptor.fromJson(json);
        String npub = d.loginNpub();
        assertNotNull(npub);
        assertEquals(64, npub.length());
        // Should be valid hex
        assertDoesNotThrow(() -> NostrUtil.hexToBytes(npub));
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

    // ── Realm derivation tests ──────────────────────────────────────────

    @Test
    void realmXpubIsDeterministic() {
        byte[] seed = new byte[64];
        seed[0] = 42;
        KeyMaster km1 = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), seed);
        KeyMaster km2 = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), seed.clone());
        assertEquals(km1.deriveRealmXpub(0), km2.deriveRealmXpub(0));
    }

    @Test
    void realmXpubFormat() {
        byte[] seed = new byte[64];
        seed[0] = 1;
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), seed);
        String xpub = km.deriveRealmXpub(0);
        assertTrue(xpub.startsWith("xpub"), "realm xpub: " + xpub);
    }

    @Test
    void realmServiceKeyDerivation() {
        byte[] seed = new byte[64];
        seed[0] = 1;
        KeyMaster km = new KeyMaster(new Bip32KeyVault(TEST_MNEMONIC), seed);
        byte[] sshKey = km.deriveRealmServiceKey(0, "ssh", 0);
        byte[] gpgKey = km.deriveRealmServiceKey(0, "gpg", 0);
        assertNotNull(sshKey);
        assertEquals(32, sshKey.length);
        // Different services produce different keys
        assertFalse(java.util.Arrays.equals(sshKey, gpgKey));
    }

    @Test
    void xpubToNpubProduces64CharHex() {
        // Use a valid xpub (m/0 from well-known seed)
        byte[] seed = new byte[64];
        seed[0] = 1;
        Bip32KeyDerivator kd = new Bip32KeyDerivator(seed);
        String xpub = kd.deriveXpub(0);
        String npub = NostrTransport.xpubToNpub(xpub);
        assertEquals(64, npub.length());
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
