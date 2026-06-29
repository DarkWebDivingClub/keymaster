package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.KeyVault;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.List;

import static club.dwdc.keymaster.GpgServiceHandlerTest.*;
import static org.junit.jupiter.api.Assertions.*;

class OpenPgpCertBuilderTest {

    @Test
    void buildPublicCert_producesValidArmor() throws Exception {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        List<KeyEntry> keys = gpgKeysForIdentity("alice@test.com");

        String armor = OpenPgpCertBuilder.buildPublicCert(
                vault, keys.get(0), keys.get(1),
                "alice@test.com", "alice@test.com",
                java.time.Instant.ofEpochSecond(1700000000));

        assertTrue(armor.contains("BEGIN PGP PUBLIC KEY BLOCK"));
        assertTrue(armor.contains("END PGP PUBLIC KEY BLOCK"));
    }

    @Test
    void buildPublicCert_isDeterministic() throws Exception {
        var vault1 = new Bip32KeyVault(TEST_MNEMONIC);
        var vault2 = new Bip32KeyVault(TEST_MNEMONIC);
        List<KeyEntry> keys1 = gpgKeysForIdentity("alice@test.com");
        List<KeyEntry> keys2 = gpgKeysForIdentity("alice@test.com");
        var time = java.time.Instant.ofEpochSecond(1700000000);

        String armor1 = OpenPgpCertBuilder.buildPublicCert(
                vault1, keys1.get(0), keys1.get(1),
                "alice@test.com", "alice@test.com", time);
        String armor2 = OpenPgpCertBuilder.buildPublicCert(
                vault2, keys2.get(0), keys2.get(1),
                "alice@test.com", "alice@test.com", time);

        assertEquals(armor1, armor2);
    }

    @Test
    void buildPublicCert_containsCertAndSignKeys() throws Exception {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        List<KeyEntry> keys = gpgKeysForIdentity("alice@test.com");

        String armor = OpenPgpCertBuilder.buildPublicCert(
                vault, keys.get(0), keys.get(1),
                "alice@test.com", "alice@test.com",
                java.time.Instant.ofEpochSecond(1700000000));

        PGPPublicKeyRing ring = new PGPPublicKeyRing(
                PGPUtil.getDecoderStream(
                        new ByteArrayInputStream(armor.getBytes(StandardCharsets.US_ASCII))),
                new BcKeyFingerprintCalculator());

        // Should have exactly 2 keys: certification primary + signing subkey
        int keyCount = 0;
        boolean hasCertKey = false;
        boolean hasSignKey = false;

        Iterator<PGPPublicKey> keyIter = ring.getPublicKeys();
        while (keyIter.hasNext()) {
            PGPPublicKey pk = keyIter.next();
            keyCount++;
            if (pk.isMasterKey()) {
                hasCertKey = hasKeyFlag(pk, KeyFlags.CERTIFY_OTHER);
            } else {
                hasSignKey = hasKeyFlag(pk, KeyFlags.SIGN_DATA);
            }
        }
        assertEquals(2, keyCount);
        assertTrue(hasCertKey, "Primary key should have CERTIFY_OTHER flag");
        assertTrue(hasSignKey, "Subkey should have SIGN_DATA flag");
    }

    @Test
    void buildPublicCert_fingerprintMatchesVaultPubkey() throws Exception {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        List<KeyEntry> keys = gpgKeysForIdentity("alice@test.com");

        // Get raw public key from vault
        byte[] certPubBytes = vault.execute(
                KeyVault.FN_GET_PUBLIC_KEY, null, keys.get(0).toVaultPath()).data();

        String armor = OpenPgpCertBuilder.buildPublicCert(
                vault, keys.get(0), keys.get(1),
                "alice@test.com", "alice@test.com",
                java.time.Instant.ofEpochSecond(1700000000));

        PGPPublicKeyRing ring = new PGPPublicKeyRing(
                PGPUtil.getDecoderStream(
                        new ByteArrayInputStream(armor.getBytes(StandardCharsets.US_ASCII))),
                new BcKeyFingerprintCalculator());

        PGPPublicKey masterKey = ring.getPublicKey();
        assertNotNull(masterKey.getFingerprint());
        assertEquals(20, masterKey.getFingerprint().length, "v4 fingerprint is 20 bytes");

        // Verify the raw Ed25519 public key bytes are embedded in the PGP key
        byte[] pgpKeyData = masterKey.getPublicKeyPacket().getKey().getEncoded();
        // The OID-prefixed key data ends with the 32-byte raw Ed25519 public key
        byte[] extractedPub = new byte[32];
        // Ed25519 public key is at the end of the encoded key data, preceded by
        // a 0x40 prefix byte (point format indicator) and the OID
        // Look for the 32 bytes at the end after the 0x40 marker
        int offset = pgpKeyData.length - 32;
        System.arraycopy(pgpKeyData, offset, extractedPub, 0, 32);
        assertArrayEquals(certPubBytes, extractedPub);
    }

    private static boolean hasKeyFlag(PGPPublicKey key, int flag) {
        Iterator<PGPSignature> sigs = key.getSignatures();
        while (sigs.hasNext()) {
            PGPSignature sig = sigs.next();
            PGPSignatureSubpacketVector hashed = sig.getHashedSubPackets();
            if (hashed != null && (hashed.getKeyFlags() & flag) != 0) {
                return true;
            }
        }
        return false;
    }
}
