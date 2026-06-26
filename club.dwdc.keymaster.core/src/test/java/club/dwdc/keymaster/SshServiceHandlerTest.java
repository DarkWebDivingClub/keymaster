package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SshServiceHandlerTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    static KeyEntry sshKeyEntry(String identity) {
        HDPath path = HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.SSH.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
            new ChildNumber(0, true)
        );
        return new KeyEntry(path, Map.of("comment", identity));
    }

    @Test
    void requestIdentities_returnsSingleKey() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new SshServiceHandler(vault, List.of(sshKeyEntry("alice@test.com")));

        List<SshIdentity> ids = handler.requestIdentities();

        assertEquals(1, ids.size());
        assertEquals(51, ids.get(0).keyBlob().length); // 4+11+4+32 = 51
        assertEquals("alice@test.com", ids.get(0).comment());
    }

    @Test
    void requestIdentities_returnsMultipleKeys() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new SshServiceHandler(vault, List.of(
                sshKeyEntry("alice@test.com"),
                sshKeyEntry("bob@test.com")
        ));

        List<SshIdentity> ids = handler.requestIdentities();

        assertEquals(2, ids.size());
    }

    @Test
    void requestIdentities_emptyWhenNoKeys() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new SshServiceHandler(vault, List.of());

        List<SshIdentity> ids = handler.requestIdentities();

        assertTrue(ids.isEmpty());
    }

    @Test
    void requestIdentities_isDeterministic() {
        var vault1 = new Bip32KeyVault(TEST_MNEMONIC);
        var handler1 = new SshServiceHandler(vault1, List.of(sshKeyEntry("alice@test.com")));
        var vault2 = new Bip32KeyVault(TEST_MNEMONIC);
        var handler2 = new SshServiceHandler(vault2, List.of(sshKeyEntry("alice@test.com")));

        List<SshIdentity> ids1 = handler1.requestIdentities();
        List<SshIdentity> ids2 = handler2.requestIdentities();

        assertArrayEquals(ids1.get(0).keyBlob(), ids2.get(0).keyBlob());
    }

    @Test
    void signRequest_producesValidSignature() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new SshServiceHandler(vault, List.of(sshKeyEntry("alice@test.com")));
        handler.setApprovalUI((m, d) -> true);

        List<SshIdentity> ids = handler.requestIdentities();
        byte[] testData = "test data to sign".getBytes();
        var request = new SshSignRequest(ids.get(0).keyBlob(), testData);

        SshSignResponse response = handler.signRequest(request);

        assertNotNull(response.signature());
        assertEquals(64, response.signature().length); // Ed25519 signature is 64 bytes
        assertEquals("ssh-ed25519", response.keyType());
    }

    @Test
    void signRequest_throwsOnKeyMismatch() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new SshServiceHandler(vault, List.of(sshKeyEntry("alice@test.com")));
        handler.setApprovalUI((m, d) -> true);

        byte[] wrongBlob = new byte[51];
        var request = new SshSignRequest(wrongBlob, "data".getBytes());

        var ex = assertThrows(IllegalArgumentException.class, () -> handler.signRequest(request));
        assertEquals("key-mismatch", ex.getMessage());
    }

    @Test
    void signRequest_worksWithMultipleKeys() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new SshServiceHandler(vault, List.of(
                sshKeyEntry("alice@test.com"),
                sshKeyEntry("bob@test.com")
        ));
        handler.setApprovalUI((m, d) -> true);

        List<SshIdentity> ids = handler.requestIdentities();
        // Sign with the second key
        byte[] testData = "test data".getBytes();
        var request = new SshSignRequest(ids.get(1).keyBlob(), testData);

        SshSignResponse response = handler.signRequest(request);

        assertNotNull(response.signature());
        assertEquals(64, response.signature().length);
    }

    @Test
    void approval_signRequestDeniedWithoutUI() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new SshServiceHandler(vault, List.of(sshKeyEntry("alice@test.com")));
        // No UI set — ASK policy should deny

        List<SshIdentity> ids = handler.requestIdentities(); // APPROVE policy, works
        var request = new SshSignRequest(ids.get(0).keyBlob(), "data".getBytes());

        assertThrows(RequestDeniedException.class, () -> handler.signRequest(request));
    }

    @Test
    void approval_signRequestApprovedWithUI() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new SshServiceHandler(vault, List.of(sshKeyEntry("alice@test.com")));
        handler.setApprovalUI((m, d) -> true);

        List<SshIdentity> ids = handler.requestIdentities();
        var request = new SshSignRequest(ids.get(0).keyBlob(), "data".getBytes());

        SshSignResponse response = handler.signRequest(request);
        assertNotNull(response.signature());
    }

    @Test
    void approval_overridePolicyToApprove() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var handler = new SshServiceHandler(vault, List.of(sshKeyEntry("alice@test.com")));
        // Override sign_request from ASK to APPROVE
        handler.setPolicy("sign_request", ApprovalPolicy.APPROVE);

        List<SshIdentity> ids = handler.requestIdentities();
        var request = new SshSignRequest(ids.get(0).keyBlob(), "data".getBytes());

        SshSignResponse response = handler.signRequest(request);
        assertNotNull(response.signature());
    }

    @Test
    void goldenTest_blobFormat() {
        // Verify buildSshEd25519KeyBlob produces the expected SSH wire format:
        // uint32(11) + "ssh-ed25519" + uint32(32) + pubkey = 51 bytes
        byte[] testPubKey = new byte[32];
        for (int i = 0; i < 32; i++) testPubKey[i] = (byte) i;

        byte[] blob = SshServiceHandler.buildSshEd25519KeyBlob(testPubKey);

        assertEquals(51, blob.length); // 4 + 11 + 4 + 32
        // First 4 bytes: big-endian length of "ssh-ed25519" = 11
        assertEquals(0, blob[0]);
        assertEquals(0, blob[1]);
        assertEquals(0, blob[2]);
        assertEquals(11, blob[3]);
        // Then the algorithm name
        assertEquals("ssh-ed25519", new String(blob, 4, 11));
        // Then 4 bytes: big-endian length of pubkey = 32
        assertEquals(0, blob[15]);
        assertEquals(0, blob[16]);
        assertEquals(0, blob[17]);
        assertEquals(32, blob[18]);
        // Then the pubkey
        for (int i = 0; i < 32; i++) {
            assertEquals((byte) i, blob[19 + i]);
        }
    }
}
