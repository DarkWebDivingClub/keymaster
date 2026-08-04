package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import nostr.crypto.schnorr.Schnorr;
import nostr.util.NostrUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.Security;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests that the identity-based transport signer produces deterministic,
 * identity-specific keys from the vault.
 */
class DeviceSignerTest {

    private static final int H = 0x80000000;
    private static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon about";

    @BeforeAll
    static void ensureBC() {
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    @Test
    void sameIdentitySameSeedProducesSameNpub() {
        Bip32KeyVault vault1 = new Bip32KeyVault(TEST_MNEMONIC);
        Bip32KeyVault vault2 = new Bip32KeyVault(TEST_MNEMONIC);

        TransportSigner signer1 = buildSigner(vault1, "alice@atlanta.com");
        TransportSigner signer2 = buildSigner(vault2, "alice@atlanta.com");

        assertEquals(signer1.getPubkey(), signer2.getPubkey());
    }

    @Test
    void differentIdentitySameSeedProducesDifferentNpub() {
        Bip32KeyVault vault = new Bip32KeyVault(TEST_MNEMONIC);

        TransportSigner signerA = buildSigner(vault, "alice@atlanta.com");
        TransportSigner signerB = buildSigner(vault, "bob@boston.com");

        assertNotEquals(signerA.getPubkey(), signerB.getPubkey());
    }

    @Test
    void signProducesValidSchnorrSignature() throws Exception {
        Bip32KeyVault vault = new Bip32KeyVault(TEST_MNEMONIC);
        TransportSigner signer = buildSigner(vault, "alice@atlanta.com");

        byte[] pubKey = NostrUtil.hexToBytes(signer.getPubkey());

        // Sign a 32-byte SHA-256 hash
        byte[] message = MessageDigest.getInstance("SHA-256")
                .digest("test message".getBytes());
        byte[] sig = signer.sign(message);

        assertNotNull(sig);
        assertEquals(64, sig.length);
        assertTrue(Schnorr.verify(message, pubKey, sig));
    }

    @Test
    void ecdhProducesCorrectSharedSecret() {
        Bip32KeyVault vault = new Bip32KeyVault(TEST_MNEMONIC);

        TransportSigner signerA = buildSigner(vault, "alice@atlanta.com");
        TransportSigner signerB = buildSigner(vault, "bob@boston.com");

        byte[] pubA = NostrUtil.hexToBytes(signerA.getPubkey());
        byte[] pubB = NostrUtil.hexToBytes(signerB.getPubkey());

        // ECDH from both sides must agree
        byte[] sharedFromA = signerA.ecdh(pubB);
        byte[] sharedFromB = signerB.ecdh(pubA);

        assertNotNull(sharedFromA);
        assertEquals(32, sharedFromA.length);
        assertArrayEquals(sharedFromA, sharedFromB);
    }

    @Test
    void pubkeyIs64CharHex() {
        Bip32KeyVault vault = new Bip32KeyVault(TEST_MNEMONIC);
        TransportSigner signer = buildSigner(vault, "alice@atlanta.com");

        String pubkey = signer.getPubkey();
        assertEquals(64, pubkey.length());
        assertTrue(pubkey.matches("[0-9a-f]{64}"));
    }

    /** Build a TransportSigner for an identity using the same path as KeyMasterController. */
    private static TransportSigner buildSigner(KeyVault vault, String identity) {
        int mangledIdentity = Bip32KeyDerivator.mangle(identity);
        int[] path = {
                44 | H, Protocol.NOSTR.coinType() | H, mangledIdentity | H,
                new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };
        return new TransportSigner() {
            @Override
            public String getPubkey() {
                byte[] compressed = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path).data();
                return NostrUtil.bytesToHex(Arrays.copyOfRange(compressed, 1, 33));
            }

            @Override
            public byte[] sign(byte[] hash) {
                return vault.execute(KeyVault.FN_SIGN, hash, path).data();
            }

            @Override
            public byte[] ecdh(byte[] peerPubKey) {
                return vault.execute(KeyVault.FN_KEY_AGREEMENT, peerPubKey, path).data();
            }
        };
    }
}
