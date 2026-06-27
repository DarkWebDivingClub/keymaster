package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.Protocol;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class GpgServiceHandlerTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    /** Fixed creation time for test determinism. */
    private static final String TEST_CREATION_TIME = "1700000000";

    /**
     * Build a GPG KeyEntry for the given identity and role.
     * Role 0 = certification, role 1 = signing.
     */
    static KeyEntry gpgKeyEntry(String identity, int role, String roleName) {
        HDPath path = HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.OPENPGP.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, role).toIndex(), true),
            new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        return new KeyEntry(path, Map.of(
                "label", identity + " / " + roleName,
                "key_type", "ed25519",
                "identity", identity,
                "creation_time", TEST_CREATION_TIME,
                "pgp_name", identity,
                "pgp_email", identity));
    }

    static List<KeyEntry> gpgKeysForIdentity(String identity) {
        return List.of(
                gpgKeyEntry(identity, 0, "certification"),
                gpgKeyEntry(identity, 1, "signing"));
    }

    @Test
    void requestIdentities_returnsTwoRoles() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new GpgServiceHandler(vault, gpgKeysForIdentity("alice@test.com"));

        List<GpgIdentity> ids = handler.requestIdentities();

        assertEquals(2, ids.size());
        assertEquals("ed25519", ids.get(0).keyType());
        assertEquals("alice@test.com / certification", ids.get(0).label());
        assertEquals(32, ids.get(0).publicKey().length);
        assertEquals("alice@test.com / signing", ids.get(1).label());
        assertEquals(32, ids.get(1).publicKey().length);
    }

    @Test
    void requestIdentities_emptyWhenNoKeys() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new GpgServiceHandler(vault, List.of());

        List<GpgIdentity> ids = handler.requestIdentities();

        assertTrue(ids.isEmpty());
    }

    @Test
    void requestIdentities_isDeterministic() {
        var vault1 = new Bip32KeyVault(TEST_MNEMONIC);
        var handler1 = new GpgServiceHandler(vault1, gpgKeysForIdentity("alice@test.com"));
        var vault2 = new Bip32KeyVault(TEST_MNEMONIC);
        var handler2 = new GpgServiceHandler(vault2, gpgKeysForIdentity("alice@test.com"));

        List<GpgIdentity> ids1 = handler1.requestIdentities();
        List<GpgIdentity> ids2 = handler2.requestIdentities();

        assertArrayEquals(ids1.get(0).publicKey(), ids2.get(0).publicKey());
        assertArrayEquals(ids1.get(1).publicKey(), ids2.get(1).publicKey());
    }

    @Test
    void requestIdentities_certAndSigningKeysDiffer() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new GpgServiceHandler(vault, gpgKeysForIdentity("alice@test.com"));

        List<GpgIdentity> ids = handler.requestIdentities();

        assertFalse(java.util.Arrays.equals(ids.get(0).publicKey(), ids.get(1).publicKey()),
                "Certification and signing keys should be different");
    }

    @Test
    void signRequest_producesValidSignature() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new GpgServiceHandler(vault, gpgKeysForIdentity("alice@test.com"));
        handler.setApprovalUI((m, d) -> true);

        List<GpgIdentity> ids = handler.requestIdentities();
        byte[] testData = "test data to sign".getBytes();
        var request = new GpgSignRequest(ids.get(0).publicKey(), testData);

        GpgSignResponse response = handler.signRequest(request);

        assertNotNull(response.signature());
        assertEquals(64, response.signature().length); // Ed25519 signature is 64 bytes
    }

    @Test
    void signRequest_worksWithSigningRole() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new GpgServiceHandler(vault, gpgKeysForIdentity("alice@test.com"));
        handler.setApprovalUI((m, d) -> true);

        List<GpgIdentity> ids = handler.requestIdentities();
        // Sign with the signing key (role 1)
        byte[] testData = "test data".getBytes();
        var request = new GpgSignRequest(ids.get(1).publicKey(), testData);

        GpgSignResponse response = handler.signRequest(request);

        assertNotNull(response.signature());
        assertEquals(64, response.signature().length);
    }

    @Test
    void signRequest_throwsOnKeyMismatch() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new GpgServiceHandler(vault, gpgKeysForIdentity("alice@test.com"));
        handler.setApprovalUI((m, d) -> true);

        byte[] wrongKey = new byte[32];
        var request = new GpgSignRequest(wrongKey, "data".getBytes());

        var ex = assertThrows(IllegalArgumentException.class, () -> handler.signRequest(request));
        assertEquals("key-mismatch", ex.getMessage());
    }

    @Test
    void getPublicCert_generatesOnTheFly() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new GpgServiceHandler(vault, gpgKeysForIdentity("alice@test.com"));

        GpgPublicCert cert = handler.getPublicCert();

        assertNotNull(cert.publicCertArmor());
        assertTrue(cert.publicCertArmor().contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }

    @Test
    void getPublicCert_throwsWhenNoKeys() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new GpgServiceHandler(vault, List.of());

        assertThrows(IllegalStateException.class, handler::getPublicCert);
    }

    @Test
    void getPublicCert_isDeterministic() {
        var vault1 = new Bip32KeyVault(TEST_MNEMONIC);
        var handler1 = new GpgServiceHandler(vault1, gpgKeysForIdentity("alice@test.com"));
        var vault2 = new Bip32KeyVault(TEST_MNEMONIC);
        var handler2 = new GpgServiceHandler(vault2, gpgKeysForIdentity("alice@test.com"));

        assertEquals(handler1.getPublicCert().publicCertArmor(),
                handler2.getPublicCert().publicCertArmor());
    }

    @Test
    void approval_signRequestDeniedWithoutUI() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new GpgServiceHandler(vault, gpgKeysForIdentity("alice@test.com"));
        // No UI set — ASK policy should deny

        List<GpgIdentity> ids = handler.requestIdentities(); // APPROVE policy, works
        var request = new GpgSignRequest(ids.get(0).publicKey(), "data".getBytes());

        assertThrows(RequestDeniedException.class, () -> handler.signRequest(request));
    }

    @Test
    void approval_signRequestApprovedWithUI() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new GpgServiceHandler(vault, gpgKeysForIdentity("alice@test.com"));
        handler.setApprovalUI((m, d) -> true);

        List<GpgIdentity> ids = handler.requestIdentities();
        var request = new GpgSignRequest(ids.get(0).publicKey(), "data".getBytes());

        GpgSignResponse response = handler.signRequest(request);
        assertNotNull(response.signature());
    }

    @Test
    void approval_overridePolicyToApprove() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new GpgServiceHandler(vault, gpgKeysForIdentity("alice@test.com"));
        handler.setPolicy("sign_request", ApprovalPolicy.APPROVE);

        List<GpgIdentity> ids = handler.requestIdentities();
        var request = new GpgSignRequest(ids.get(0).publicKey(), "data".getBytes());

        GpgSignResponse response = handler.signRequest(request);
        assertNotNull(response.signature());
    }
}
