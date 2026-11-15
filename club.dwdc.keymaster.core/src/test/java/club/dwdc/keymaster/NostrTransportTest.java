package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import nostr.crypto.nip44.EncryptedPayloads;
import nostr.crypto.schnorr.Schnorr;
import nostr.util.NostrUtil;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.crypto.MnemonicCode;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Nostr event building and crypto (no relay needed).
 */
class NostrTransportTest {

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
    void nip44VaultBackedEncryptDecryptRoundtrip() throws Exception {
        // Create two vault-backed signers (sender = deviceA, recipient = deviceB)
        Bip32KeyVault vaultA = new Bip32KeyVault(TEST_MNEMONIC);
        Bip32KeyVault vaultB = new Bip32KeyVault(TEST_MNEMONIC);

        TransportSigner signerA = buildTestSigner(vaultA, "alice@atlanta.com");
        TransportSigner signerB = buildTestSigner(vaultB, "bob@boston.com");

        byte[] pubA = NostrUtil.hexToBytes(signerA.getPubkey());
        byte[] pubB = NostrUtil.hexToBytes(signerB.getPubkey());

        // ECDH from both sides must produce the same shared X
        byte[] sharedXfromA = signerA.ecdh(pubB);
        byte[] sharedXfromB = signerB.ecdh(pubA);
        assertArrayEquals(sharedXfromA, sharedXfromB);

        // Derive conversation key and do encrypt/decrypt round-trip
        byte[] convKey = NostrTransport.deriveNip44ConversationKey(sharedXfromA);
        byte[] nonce = NostrUtil.createRandomByteArray(32);

        String plaintext = "vault-backed round-trip test";
        String encrypted = EncryptedPayloads.encrypt(plaintext, convKey, nonce);
        String decrypted = EncryptedPayloads.decrypt(encrypted, convKey);
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

    // ── sender binding ────────────────────────────────────────────────────

    @Test
    void serviceRequestFromAnotherChannelsAvatarKeyIsDropped() throws Exception {
        // Encrypted to KM's ssh channel key, but sent from the avatar's gpg key.
        Delivery d = deliverServiceRequest(List.of("gpg", "ssh"), "gpg", "ssh");

        assertTrue(d.dispatched().isEmpty(), "must not reach the service handler");
        assertEquals(0, d.eventsSent(), "must not send a response");
    }

    @Test
    void serviceRequestFromTheChannelsOwnAvatarKeyIsDispatched() throws Exception {
        // Positive control for the test above: same request, the bound sender.
        Delivery d = deliverServiceRequest(List.of("gpg", "ssh"), "ssh", "ssh");

        assertEquals(List.of("ssh"), d.dispatched());
        assertEquals(1, d.eventsSent(), "one response event");
    }

    @Test
    void x509RequestFromTheGpgAvatarKeyIsDropped() throws Exception {
        // 37.1.3: encrypted to KM's x509 channel key, sent from the avatar's gpg key.
        Delivery dropped = deliverServiceRequest(List.of("gpg", "x509"), "gpg", "x509");
        assertTrue(dropped.dispatched().isEmpty());
        assertEquals(0, dropped.eventsSent());

        Delivery control = deliverServiceRequest(List.of("gpg", "x509"), "x509", "x509");
        assertEquals(List.of("x509"), control.dispatched());
        assertEquals(1, control.eventsSent());
    }

    // ── x509 channel golden value (Rust side) ─────────────────────────────

    @Test
    void x509ChannelGolden() {
        byte[] seed = MnemonicCode.toSeed(List.of(TEST_MNEMONIC.split(" ")), "");
        assertEquals("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
                + "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
                NostrUtil.bytesToHex(seed));

        String xpub = HDKeyDerivation.deriveChildKey(
                        HDKeyDerivation.createMasterPrivateKey(seed), new ChildNumber(0))
                .serializePubB58(BitcoinNetwork.MAINNET);
        assertEquals("xpub68jrRzQfUmwSaf5Y37Yd5uwfnMRxiR14M3HBonDr91GB7GKEh7R9Mvu2UeCtbASfX"
                + "Z9FdNo9FwFx6a37HNXUDiXVQFXuadXmevRBa3y7rL8", xpub);

        assertEquals("09d8987776ec7b88ac17e00d02e887fc1a99b9b36741a915537b4951b6ecd8b5",
                NostrTransport.deriveServicePubkeyFromXpub(xpub, Bip32KeyDerivator.mangle("x509"), 0));
    }

    /** What happened to one delivered event. */
    record Delivery(List<String> dispatched, long eventsSent) {}

    /**
     * Attach-free channel setup, then deliver one request event.
     *
     * <p>The avatar login key is m/0 of the test seed; KM's channel keys come
     * from the vault at {@code RealmPaths.connector(1, xpub)/mangle(svc)/0},
     * exactly as after an attach. The event is encrypted from the avatar's
     * {@code fromService} channel key to KM's {@code toService} channel key.
     */
    static Delivery deliverServiceRequest(List<String> services, String fromService,
                                          String toService) throws Exception {
        Bip32KeyVault vault = new Bip32KeyVault(TEST_MNEMONIC);
        byte[] seed = MnemonicCode.toSeed(List.of(TEST_MNEMONIC.split(" ")), "");
        DeterministicKey avatarLogin = HDKeyDerivation.deriveChildKey(
                HDKeyDerivation.createMasterPrivateKey(seed), new ChildNumber(0));
        String avatarXpub = avatarLogin.serializePubB58(BitcoinNetwork.MAINNET);
        int[] connectorPath = RealmPaths.connector(1, avatarXpub);

        RecordingRelay relay = new RecordingRelay();
        List<String> dispatched = new ArrayList<>();
        NostrTransport transport = new NostrTransport(
                new VaultTransportSigner(vault, IdentityPaths.nostr(new Identity("alice@atlanta.com"))));
        transport.connect(relay);
        transport.setRealmVault(vault, connectorPath);
        transport.setServiceRequestHandler((serviceType, method, params) -> {
            dispatched.add(serviceType);
            JsonObject ok = new JsonObject();
            ok.add("result", new JsonObject());
            return ok;
        });
        transport.deriveServiceChannels(avatarXpub, services);

        // Sender: the avatar's channel key for fromService (it holds the private half).
        DeterministicKey sender = HDKeyDerivation.deriveChildKey(
                HDKeyDerivation.deriveChildKey(avatarLogin,
                        new ChildNumber(Bip32KeyDerivator.mangle(fromService))),
                new ChildNumber(0));
        byte[] senderPub = Arrays.copyOfRange(sender.getPubKey(), 1, 33);

        // Recipient: KM's channel key for toService.
        byte[] kmCompressed = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null,
                RealmPaths.serviceChannel(connectorPath, toService, 0)).data();
        byte[] kmPub = Arrays.copyOfRange(kmCompressed, 1, 33);

        String request = "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\""
                + toService + ".request_identities\",\"params\":{}}";
        String content = NostrTransport.encrypt(request, sender.getPrivKeyBytes(), kmPub);

        // Non-vacuous: KM's toService channel key does decrypt this event, so a
        // drop can only come from the sender-binding check, not from decryption.
        byte[] sharedX = vault.execute(KeyVault.FN_KEY_AGREEMENT, senderPub,
                RealmPaths.serviceChannel(connectorPath, toService, 0)).data();
        assertEquals(request, EncryptedPayloads.decrypt(content,
                NostrTransport.deriveNip44ConversationKey(sharedX)));

        JsonArray tags = new JsonArray();
        JsonArray pTag = new JsonArray();
        pTag.add("p");
        pTag.add(NostrUtil.bytesToHex(kmPub));
        tags.add(pTag);
        String senderHex = NostrUtil.bytesToHex(senderPub);
        long createdAt = 1700000000L;

        JsonObject event = new JsonObject();
        event.addProperty("id", NostrTransport.computeEventId(senderHex, createdAt, 27235, tags, content));
        event.addProperty("pubkey", senderHex);
        event.addProperty("created_at", createdAt);
        event.addProperty("kind", 27235);
        event.add("tags", tags);
        event.addProperty("content", content);

        long before = relay.eventsSent();
        transport.handleIncomingEvent(event);
        return new Delivery(dispatched, relay.eventsSent() - before);
    }

    /** RelayClient that records what is sent and never connects anywhere. */
    static final class RecordingRelay implements RelayClient {
        final List<String> sent = new ArrayList<>();

        @Override public void setListener(Listener listener) { }
        @Override public void connect() { }
        @Override public void send(String message) { sent.add(message); }
        @Override public void close() { }

        long eventsSent() {
            return sent.stream().filter(m -> m.startsWith("[\"EVENT\"")).count();
        }
    }

    /** Build a test TransportSigner for a given identity. */
    private static TransportSigner buildTestSigner(KeyVault vault, String identity) {
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
                return NostrUtil.bytesToHex(java.util.Arrays.copyOfRange(compressed, 1, 33));
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
