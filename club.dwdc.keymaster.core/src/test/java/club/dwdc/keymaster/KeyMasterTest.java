package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.nostr.KeyVaultIdentity;
import nostr.util.NostrUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for KeyMaster identity derivation (no relay needed).
 */
class KeyMasterTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    @Test
    void createFromMnemonic() {
        KeyMaster km = new KeyMaster(TEST_MNEMONIC, "alice@atlanta.com");
        assertNotNull(km.getPubKeyHex());
        assertEquals(64, km.getPubKeyHex().length()); // 32 bytes hex
    }

    @Test
    void deterministicIdentity() {
        KeyMaster km1 = new KeyMaster(TEST_MNEMONIC, "alice@atlanta.com");
        KeyMaster km2 = new KeyMaster(TEST_MNEMONIC, "alice@atlanta.com");
        assertEquals(km1.getPubKeyHex(), km2.getPubKeyHex());
    }

    @Test
    void differentIdentitiesDifferentKeys() {
        KeyMaster alice = new KeyMaster(TEST_MNEMONIC, "alice@atlanta.com");
        KeyMaster bob = new KeyMaster(TEST_MNEMONIC, "bob@ssh.com");
        assertNotEquals(alice.getPubKeyHex(), bob.getPubKeyHex());
    }

    @Test
    void matchesKeyVaultIdentity() {
        KeyMaster km = new KeyMaster(TEST_MNEMONIC, "alice@atlanta.com");

        Bip32KeyVault vault = new Bip32KeyVault(TEST_MNEMONIC);
        KeyVaultIdentity kvi = new KeyVaultIdentity(vault, "alice@atlanta.com");
        String expected = NostrUtil.bytesToHex(kvi.getPublicKey().getRawData());

        assertEquals(expected, km.getPubKeyHex());
    }
}
