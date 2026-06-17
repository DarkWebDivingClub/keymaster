package club.dwdc.keymaster;

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
        KeyMaster km = new KeyMaster(TEST_MNEMONIC);
        km.createIdentity("alice@atlanta.com");
        assertNotNull(km.getPubKeyHex());
        assertEquals(64, km.getPubKeyHex().length()); // 32 bytes hex
    }

    @Test
    void deterministicIdentity() {
        KeyMaster km1 = new KeyMaster(TEST_MNEMONIC);
        km1.createIdentity("alice@atlanta.com");
        KeyMaster km2 = new KeyMaster(TEST_MNEMONIC);
        km2.createIdentity("alice@atlanta.com");
        assertEquals(km1.getPubKeyHex(), km2.getPubKeyHex());
    }

    @Test
    void differentIdentitiesDifferentKeys() {
        KeyMaster alice = new KeyMaster(TEST_MNEMONIC);
        alice.createIdentity("alice@atlanta.com");
        KeyMaster bob = new KeyMaster(TEST_MNEMONIC);
        bob.createIdentity("bob@ssh.com");
        assertNotEquals(alice.getPubKeyHex(), bob.getPubKeyHex());
    }

    @Test
    void matchesKeyVaultIdentity() {
        KeyMaster km = new KeyMaster(TEST_MNEMONIC);
        km.createIdentity("alice@atlanta.com");

        Bip32KeyVault vault = new Bip32KeyVault(TEST_MNEMONIC);
        KeyVaultIdentity kvi = new KeyVaultIdentity(vault, "alice@atlanta.com");
        String expected = NostrUtil.bytesToHex(kvi.getPublicKey().getRawData());

        assertEquals(expected, km.getPubKeyHex());
    }

    @Test
    void avatarDescriptorFromJson() {
        String json = """
                {
                  "relay": "ws://localhost:7777",
                  "pubkey": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
                  "services": ["ssh", "nostr"]
                }
                """;
        AvatarDescriptor d = AvatarDescriptor.fromJson(json);
        assertEquals("ws://localhost:7777", d.relay());
        assertEquals("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234", d.pubkey());
        assertEquals(List.of("ssh", "nostr"), d.services());
    }

    @Test
    void avatarDescriptorRejectsNullRelay() {
        assertThrows(IllegalArgumentException.class, () ->
                new AvatarDescriptor(null, "abcd1234", List.of()));
    }

    @Test
    void avatarDescriptorRejectsNullPubkey() {
        assertThrows(IllegalArgumentException.class, () ->
                new AvatarDescriptor("ws://localhost:7777", null, List.of()));
    }

    @Test
    void avatarDescriptorDefaultsServicesToEmptyList() {
        String json = """
                {
                  "relay": "ws://localhost:7777",
                  "pubkey": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
                }
                """;
        AvatarDescriptor d = AvatarDescriptor.fromJson(json);
        assertEquals(List.of(), d.services());
    }
}
