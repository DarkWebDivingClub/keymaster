package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.VaultResult;
import nostr.crypto.schnorr.Schnorr;
import nostr.util.NostrUtil;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that a vault-backed {@link NostrIdentitySigner} produces valid
 * BIP-340 Schnorr signatures.
 */
class NostrIdentitySignerTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    private static final int H = 0x80000000;

    @Test
    void vaultBackedSigner_producesValidSignature() throws Exception {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);

        int identityIndex = Bip32KeyDerivator.mangle("alice@atlanta.com") | H;
        int[] nostrPath = {
                44 | H,
                Protocol.NOSTR.coinType() | H,
                identityIndex,
                new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };

        NostrIdentitySigner signer = new NostrIdentitySigner() {
            @Override
            public String getPubkey() {
                byte[] compressed = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, nostrPath).data();
                return NostrUtil.bytesToHex(java.util.Arrays.copyOfRange(compressed, 1, 33));
            }

            @Override
            public byte[] sign(byte[] hash) {
                return vault.execute(KeyVault.FN_SIGN, hash, nostrPath).data();
            }
        };

        // Verify pubkey
        String pubkey = signer.getPubkey();
        assertNotNull(pubkey);
        assertEquals(64, pubkey.length());

        // Sign a test hash
        byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest("test connector data".getBytes());
        byte[] sig = signer.sign(hash);
        assertNotNull(sig);
        assertEquals(64, sig.length);

        // Verify signature with Schnorr
        byte[] pubkeyBytes = NostrUtil.hexToBytes(pubkey);
        assertTrue(Schnorr.verify(hash, pubkeyBytes, sig),
                "Vault-backed signer must produce a valid Schnorr signature");
    }
}
