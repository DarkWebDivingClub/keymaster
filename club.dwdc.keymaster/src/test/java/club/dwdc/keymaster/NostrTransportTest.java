package club.dwdc.keymaster;

import com.google.gson.JsonArray;
import nostr.crypto.nip44.EncryptedPayloads;
import nostr.crypto.schnorr.Schnorr;
import nostr.util.NostrUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Nostr event building and crypto (no relay needed).
 */
class NostrTransportTest {

    @BeforeAll
    static void ensureBC() {
        if (Security.getProvider("BC") == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    // Deterministic test key from "abandon...about" mnemonic, alice@atlanta.com identity
    private static byte[] testPrivKey() {
        // Use a fixed 32-byte key for deterministic tests
        return NostrUtil.hexToBytes(
                "0000000000000000000000000000000000000000000000000000000000000001");
    }

    private static byte[] testPubKey() throws Exception {
        return Schnorr.genPubKey(testPrivKey());
    }

    @Test
    void eventIdComputation() throws Exception {
        byte[] pubKey = testPubKey();
        String pubKeyHex = NostrUtil.bytesToHex(pubKey);
        long createdAt = 1700000000L;
        int kind = 27235;
        JsonArray tags = new JsonArray();
        String content = "test content";

        String eventId = NostrTransport.computeEventId(pubKeyHex, createdAt, kind, tags, content);

        assertNotNull(eventId);
        assertEquals(64, eventId.length()); // SHA-256 hex
        // Deterministic: same inputs -> same event ID
        String eventId2 = NostrTransport.computeEventId(pubKeyHex, createdAt, kind, tags, content);
        assertEquals(eventId, eventId2);
    }

    @Test
    void nip44EncryptDecryptRoundtrip() throws Exception {
        // Sender and recipient are different keys
        byte[] senderPriv = NostrUtil.hexToBytes(
                "0000000000000000000000000000000000000000000000000000000000000001");
        byte[] recipientPriv = NostrUtil.hexToBytes(
                "0000000000000000000000000000000000000000000000000000000000000002");
        byte[] senderPub = Schnorr.genPubKey(senderPriv);
        byte[] recipientPub = Schnorr.genPubKey(recipientPriv);

        String plaintext = "hello from keymaster";
        String encrypted = NostrTransport.encrypt(plaintext, senderPriv, recipientPub);

        assertNotNull(encrypted);
        assertNotEquals(plaintext, encrypted);

        String decrypted = NostrTransport.decrypt(encrypted, recipientPriv, senderPub);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void nip44ConversationKeyMatchesSpecVector() {
        // NIP-44 test vector: sec1=000...001, pub2 derived from sec2=000...002
        // Expected conversation_key (HKDF-based): c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d
        // The old PBKDF2 implementation would produce a different key, so this
        // test proves the correct HKDF implementation is on the classpath.
        String sec1 = "0000000000000000000000000000000000000000000000000000000000000001";
        String pub2 = "02" + NostrUtil.bytesToHex(Schnorr.genPubKey(NostrUtil.hexToBytes(
                "0000000000000000000000000000000000000000000000000000000000000002")));

        byte[] conversationKey = EncryptedPayloads.getConversationKey(sec1, pub2);

        assertEquals(
                "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d",
                NostrUtil.bytesToHex(conversationKey));
    }

    @Test
    void schnorrSignVerify() throws Exception {
        byte[] privKey = testPrivKey();
        byte[] pubKey = testPubKey();

        // Create a fake event ID (32-byte hash)
        String fakeEventId = NostrTransport.computeEventId(
                NostrUtil.bytesToHex(pubKey), 1700000000L, 27235, new JsonArray(), "test");

        String sigHex = NostrTransport.signEvent(fakeEventId, privKey);
        assertNotNull(sigHex);
        assertEquals(128, sigHex.length()); // 64 bytes hex

        // Verify signature
        byte[] eventIdBytes = NostrUtil.hexToBytes(fakeEventId);
        byte[] sigBytes = NostrUtil.hex128ToBytes(sigHex);
        assertTrue(Schnorr.verify(eventIdBytes, pubKey, sigBytes));
    }
}
