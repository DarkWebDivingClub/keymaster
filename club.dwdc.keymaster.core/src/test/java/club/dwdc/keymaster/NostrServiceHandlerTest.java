package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class NostrServiceHandlerTest {

    static final String ALICE_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    static final String BOB_MNEMONIC =
            "zoo zoo zoo zoo zoo zoo " +
            "zoo zoo zoo zoo zoo wrong";

    static KeyEntry nostrKeyEntry(String identity) {
        HDPath path = HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.NOSTR.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex(), true),
            new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        return new KeyEntry(path, Map.of("identity", identity));
    }

    @Test
    void getPublicKeys_returnsSingleKey() {
        var vault = new Bip32KeyVault(ALICE_MNEMONIC);
        var handler = new NostrServiceHandler(vault, List.of(nostrKeyEntry("alice@test.com")));

        List<NostrPublicKey> keys = handler.getPublicKeys();

        assertEquals(1, keys.size());
        assertEquals(32, keys.get(0).publicKey().length); // x-only Schnorr pubkey
    }

    @Test
    void getPublicKeys_returnsMultipleKeys() {
        var vault = new Bip32KeyVault(ALICE_MNEMONIC);
        var handler = new NostrServiceHandler(vault, List.of(
                nostrKeyEntry("alice@test.com"),
                nostrKeyEntry("bob@test.com")
        ));

        List<NostrPublicKey> keys = handler.getPublicKeys();

        assertEquals(2, keys.size());
    }

    @Test
    void getPublicKeys_emptyWhenNoKeys() {
        var vault = new Bip32KeyVault(ALICE_MNEMONIC);
        var handler = new NostrServiceHandler(vault, List.of());

        List<NostrPublicKey> keys = handler.getPublicKeys();

        assertTrue(keys.isEmpty());
    }

    @Test
    void getPublicKeys_isDeterministic() {
        var vault1 = new Bip32KeyVault(ALICE_MNEMONIC);
        var handler1 = new NostrServiceHandler(vault1, List.of(nostrKeyEntry("alice@test.com")));
        var vault2 = new Bip32KeyVault(ALICE_MNEMONIC);
        var handler2 = new NostrServiceHandler(vault2, List.of(nostrKeyEntry("alice@test.com")));

        List<NostrPublicKey> keys1 = handler1.getPublicKeys();
        List<NostrPublicKey> keys2 = handler2.getPublicKeys();

        assertArrayEquals(keys1.get(0).publicKey(), keys2.get(0).publicKey());
    }

    @Test
    void signEvent_producesValidSignature() {
        var vault = new Bip32KeyVault(ALICE_MNEMONIC);
        var handler = new NostrServiceHandler(vault, List.of(nostrKeyEntry("alice@test.com")));
        handler.setApprovalUI((m, d) -> true);

        byte[] pubkey = handler.getPublicKeys().get(0).publicKey();
        byte[] eventHash = new byte[32]; // simulated pre-hashed event ID
        System.arraycopy("test event data 32byteshash!!!!".getBytes(), 0, eventHash, 0, 30);
        var request = new NostrSignEventRequest(pubkey, eventHash);

        NostrSignEventResponse response = handler.signEvent(request);

        assertNotNull(response.signature());
        assertEquals(64, response.signature().length); // Schnorr signature
    }

    @Test
    void signEvent_throwsOnKeyMismatch() {
        var vault = new Bip32KeyVault(ALICE_MNEMONIC);
        var handler = new NostrServiceHandler(vault, List.of(nostrKeyEntry("alice@test.com")));
        handler.setApprovalUI((m, d) -> true);

        byte[] wrongPubkey = new byte[32];
        byte[] eventHash = new byte[32];
        var request = new NostrSignEventRequest(wrongPubkey, eventHash);

        var ex = assertThrows(IllegalArgumentException.class, () -> handler.signEvent(request));
        assertEquals("key-mismatch", ex.getMessage());
    }

    @Test
    void signEvent_deniedWithoutUI() {
        var vault = new Bip32KeyVault(ALICE_MNEMONIC);
        var handler = new NostrServiceHandler(vault, List.of(nostrKeyEntry("alice@test.com")));

        byte[] pubkey = handler.getPublicKeys().get(0).publicKey();
        byte[] eventHash = new byte[32];
        var request = new NostrSignEventRequest(pubkey, eventHash);

        assertThrows(RequestDeniedException.class, () -> handler.signEvent(request));
    }

    @Test
    void nip04_encryptDecryptRoundTrip() {
        var vault = new Bip32KeyVault(ALICE_MNEMONIC);
        var handler = new NostrServiceHandler(vault, List.of(nostrKeyEntry("alice@test.com")));

        byte[] alicePubkey = handler.getPublicKeys().get(0).publicKey();
        // Encrypt to self (alice → alice): uses alice's key for both ECDH sides
        var encReq = new NostrEncryptRequest(alicePubkey, alicePubkey, "hello-nip04");
        NostrEncryptResponse encResp = handler.nip04Encrypt(encReq);

        assertNotNull(encResp.ciphertext());
        assertTrue(encResp.ciphertext().contains("?iv="), "NIP-04 format: base64?iv=base64");

        var decReq = new NostrDecryptRequest(alicePubkey, alicePubkey, encResp.ciphertext());
        NostrDecryptResponse decResp = handler.nip04Decrypt(decReq);

        assertEquals("hello-nip04", decResp.plaintext());
    }

    @Test
    void nip44_encryptDecryptRoundTrip() {
        var vault = new Bip32KeyVault(ALICE_MNEMONIC);
        var handler = new NostrServiceHandler(vault, List.of(nostrKeyEntry("alice@test.com")));

        byte[] alicePubkey = handler.getPublicKeys().get(0).publicKey();
        var encReq = new NostrEncryptRequest(alicePubkey, alicePubkey, "hello-nip44");
        NostrEncryptResponse encResp = handler.nip44Encrypt(encReq);

        assertNotNull(encResp.ciphertext());

        var decReq = new NostrDecryptRequest(alicePubkey, alicePubkey, encResp.ciphertext());
        NostrDecryptResponse decResp = handler.nip44Decrypt(decReq);

        assertEquals("hello-nip44", decResp.plaintext());
    }

    @Test
    void nip04_crossPeerEncryptDecrypt() {
        var aliceVault = new Bip32KeyVault(ALICE_MNEMONIC);
        var aliceHandler = new NostrServiceHandler(aliceVault,
                List.of(nostrKeyEntry("alice@test.com")));

        var bobVault = new Bip32KeyVault(BOB_MNEMONIC);
        var bobHandler = new NostrServiceHandler(bobVault,
                List.of(nostrKeyEntry("bob@test.com")));

        byte[] alicePub = aliceHandler.getPublicKeys().get(0).publicKey();
        byte[] bobPub = bobHandler.getPublicKeys().get(0).publicKey();

        // Alice encrypts for Bob
        var encReq = new NostrEncryptRequest(alicePub, bobPub, "cross-peer-nip04");
        NostrEncryptResponse encResp = aliceHandler.nip04Encrypt(encReq);

        // Bob decrypts from Alice
        var decReq = new NostrDecryptRequest(bobPub, alicePub, encResp.ciphertext());
        NostrDecryptResponse decResp = bobHandler.nip04Decrypt(decReq);

        assertEquals("cross-peer-nip04", decResp.plaintext());
    }

    @Test
    void nip44_crossPeerEncryptDecrypt() {
        var aliceVault = new Bip32KeyVault(ALICE_MNEMONIC);
        var aliceHandler = new NostrServiceHandler(aliceVault,
                List.of(nostrKeyEntry("alice@test.com")));

        var bobVault = new Bip32KeyVault(BOB_MNEMONIC);
        var bobHandler = new NostrServiceHandler(bobVault,
                List.of(nostrKeyEntry("bob@test.com")));

        byte[] alicePub = aliceHandler.getPublicKeys().get(0).publicKey();
        byte[] bobPub = bobHandler.getPublicKeys().get(0).publicKey();

        // Alice encrypts for Bob
        var encReq = new NostrEncryptRequest(alicePub, bobPub, "cross-peer-nip44");
        NostrEncryptResponse encResp = aliceHandler.nip44Encrypt(encReq);

        // Bob decrypts from Alice
        var decReq = new NostrDecryptRequest(bobPub, alicePub, encResp.ciphertext());
        NostrDecryptResponse decResp = bobHandler.nip44Decrypt(decReq);

        assertEquals("cross-peer-nip44", decResp.plaintext());
    }

    @Test
    void nip04_decryptInvalidFormat() {
        var vault = new Bip32KeyVault(ALICE_MNEMONIC);
        var handler = new NostrServiceHandler(vault, List.of(nostrKeyEntry("alice@test.com")));

        byte[] pubkey = handler.getPublicKeys().get(0).publicKey();
        var request = new NostrDecryptRequest(pubkey, pubkey, "invalid-no-iv-separator");

        assertThrows(IllegalArgumentException.class, () -> handler.nip04Decrypt(request));
    }
}
