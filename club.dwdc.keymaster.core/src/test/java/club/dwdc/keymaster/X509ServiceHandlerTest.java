package club.dwdc.keymaster;

import club.dwdc.keymaster.X509CertCheck.Verdict;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link X509ServiceHandler} — the 37.1.3 wire contract. Fixtures are the
 * 37.1.2 certificates in {@code src/test/resources/x509/}, issued over Alice's
 * TLS client key under the test mnemonic.
 */
class X509ServiceHandlerTest {

    private static final Identity ALICE = new Identity("alice@atlanta.com");
    private static final Identity BOB = new Identity("bob@boston.com");
    private static final String ALICE_PATH = "m/44'/1240'/1955269225'/196866'/0'";

    private static Bip32KeyVault vault;

    private InMemoryKeyMetaDataStore store;
    private X509ServiceHandler handler;

    @BeforeAll
    static void setUpVault() {
        // BC first, as KeyMaster does at runtime: parsing and verifying must still use SUN.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        vault = new Bip32KeyVault(RealmTest.TEST_MNEMONIC);
    }

    @BeforeEach
    void setUp() {
        store = new InMemoryKeyMetaDataStore();
        handler = new X509ServiceHandler(vault, List.of(ALICE), store);
        handler.setApprovalUI((method, description) -> true);
    }

    // ── golden values ─────────────────────────────────────────────────────

    @Test
    void mangleX509Golden() {
        assertEquals(1603287476, Bip32KeyDerivator.mangle("x509"));
        assertEquals(0x5f9039b4, Bip32KeyDerivator.mangle("x509"));
    }

    @Test
    void servesExactlyTheTemplatePathsAsKeys() {
        assertEquals(List.of(IdentityPaths.hdPath(IdentityPaths.x509(ALICE, X509Role.TLS_CLIENT))),
                handler.keys().stream().map(KeyEntry::path).toList());
        assertEquals(ALICE_PATH, IdentityPaths.pathString(IdentityPaths.x509(ALICE, X509Role.TLS_CLIENT)));
    }

    // ── list ──────────────────────────────────────────────────────────────

    @Test
    void list_withoutCertificate() {
        X509ListResponse response = handler.list();

        assertEquals(1, response.keys().size());
        X509Key key = response.keys().get(0);
        assertEquals("alice@atlanta.com tls-client", key.label());
        assertEquals(ALICE_PATH, key.path());
        assertArrayEquals(X509CertCheck.vaultPoint(vault, ALICE, X509Role.TLS_CLIENT), key.publicKey());
        assertEquals(65, key.publicKey().length);
        assertEquals(0x04, key.publicKey()[0]);
        assertArrayEquals(sha256(X509CertCheck.expectedSpki(key.publicKey())), key.id());
        assertEquals(32, key.id().length);
        assertNull(key.cert());
    }

    @Test
    void list_withStoredCertificate() throws Exception {
        byte[] der = der("tls-client-ok.pem");
        store.addKey(X509CertSlot.with(aliceEntry(), der));

        assertArrayEquals(der, handler.list().keys().get(0).cert());
    }

    @Test
    void list_wireShape_certAbsentWhenNone() {
        JsonObject result = dispatch("list", new JsonObject()).getAsJsonObject("result");
        JsonObject key = result.getAsJsonArray("keys").get(0).getAsJsonObject();

        assertEquals("alice@atlanta.com tls-client", key.get("label").getAsString());
        assertEquals(ALICE_PATH, key.get("path").getAsString());
        assertEquals(65, Base64.getDecoder().decode(key.get("public_key").getAsString()).length);
        assertEquals(32, Base64.getDecoder().decode(key.get("id").getAsString()).length);
        assertFalse(key.has("cert"), "no certificate means no cert field");
    }

    @Test
    void list_wireShape_certIsBase64Der() throws Exception {
        byte[] der = der("tls-client-ok.pem");
        store.addKey(X509CertSlot.with(aliceEntry(), der));

        JsonObject key = dispatch("list", new JsonObject()).getAsJsonObject("result")
                .getAsJsonArray("keys").get(0).getAsJsonObject();
        assertArrayEquals(der, Base64.getDecoder().decode(key.get("cert").getAsString()));
    }

    @Test
    void list_approvedWithoutUI() {
        handler.setApprovalUI(null);
        assertEquals(1, handler.list().keys().size());
    }

    // ── sign ──────────────────────────────────────────────────────────────

    @Test
    void sign_verifiesWithJdkAgainstListedPublicKey() throws Exception {
        byte[] message = "37.1.3 sign".getBytes(StandardCharsets.UTF_8);
        byte[] digest = sha256(message);

        byte[] rs = handler.sign(new X509SignRequest(ALICE_PATH, digest)).signature();
        assertEquals(64, rs.length);

        byte[] point = handler.list().keys().get(0).publicKey();
        PublicKey publicKey = KeyFactory.getInstance("EC", "SunEC")
                .generatePublic(new X509EncodedKeySpec(X509CertCheck.expectedSpki(point)));
        Signature verifier = Signature.getInstance("SHA256withECDSA", "SunEC");
        verifier.initVerify(publicKey);
        verifier.update(message);
        assertTrue(verifier.verify(rawToDer(rs)));
    }

    @Test
    void sign_wireShape() {
        JsonObject params = new JsonObject();
        params.addProperty("path", ALICE_PATH);
        params.addProperty("digest", Base64.getEncoder().encodeToString(new byte[32]));

        JsonObject response = dispatch("sign", params);
        byte[] signature = Base64.getDecoder().decode(
                response.getAsJsonObject("result").get("signature").getAsString());
        assertEquals(64, signature.length);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 31, 33, 64})
    void sign_invalidDigest(int length) {
        var e = assertThrows(IllegalArgumentException.class,
                () -> handler.sign(new X509SignRequest(ALICE_PATH, new byte[length])));
        assertEquals("invalid-digest", e.getMessage());
    }

    @Test
    void sign_nullDigest() {
        var e = assertThrows(IllegalArgumentException.class,
                () -> handler.sign(new X509SignRequest(ALICE_PATH, null)));
        assertEquals("invalid-digest", e.getMessage());
    }

    @Test
    void sign_invalidDigest_wireMessage() {
        JsonObject params = new JsonObject();
        params.addProperty("path", ALICE_PATH);
        params.addProperty("digest", Base64.getEncoder().encodeToString(new byte[31]));

        assertEquals("invalid-digest", dispatch("sign", params).get("error").getAsString());
    }

    @Test
    void sign_unknownPath_sshPathOfSameIdentity() {
        String sshPath = IdentityPaths.pathString(IdentityPaths.ssh(ALICE));
        var e = assertThrows(IllegalArgumentException.class,
                () -> handler.sign(new X509SignRequest(sshPath, new byte[32])));
        assertEquals("unknown-path", e.getMessage());
    }

    @Test
    void sign_unknownPath_anotherIdentitysX509Path() {
        String bobPath = IdentityPaths.pathString(IdentityPaths.x509(BOB, X509Role.TLS_CLIENT));
        var e = assertThrows(IllegalArgumentException.class,
                () -> handler.sign(new X509SignRequest(bobPath, new byte[32])));
        assertEquals("unknown-path", e.getMessage());
    }

    @Test
    void sign_unknownPath_noNormalising() {
        // Same path with H instead of ' — equal after parsing, but not the same string.
        String hPath = ALICE_PATH.replace('\'', 'H');
        var e = assertThrows(IllegalArgumentException.class,
                () -> handler.sign(new X509SignRequest(hPath, new byte[32])));
        assertEquals("unknown-path", e.getMessage());
    }

    @Test
    void sign_deniedWithoutUI() {
        handler.setApprovalUI(null);
        assertThrows(RequestDeniedException.class,
                () -> handler.sign(new X509SignRequest(ALICE_PATH, new byte[32])));
    }

    @Test
    void sign_approvalDescriptionCarriesLabel() {
        StringBuilder seen = new StringBuilder();
        handler.setApprovalUI((method, description) -> {
            seen.append(method).append('|').append(description);
            return true;
        });
        handler.sign(new X509SignRequest(ALICE_PATH, new byte[32]));
        assertEquals("sign|X.509 signing request: alice@atlanta.com tls-client", seen.toString());
    }

    // ── import ────────────────────────────────────────────────────────────

    @Test
    void import_acceptedIsStoredAndListed() throws Exception {
        byte[] der = der("tls-client-ok.pem");

        X509ImportResponse response = handler.importCert(new X509ImportRequest(der));

        assertEquals(Verdict.ACCEPTED, response.verdict());
        assertTrue(response.stored());
        assertArrayEquals(der, storedCert().orElseThrow());
        assertArrayEquals(der, handler.list().keys().get(0).cert());
    }

    @Test
    void import_pemIsStoredAsDer() throws Exception {
        byte[] pem = fixture("tls-client-ok.pem");

        assertTrue(handler.importCert(new X509ImportRequest(pem)).stored());
        assertArrayEquals(der("tls-client-ok.pem"), storedCert().orElseThrow());
    }

    @Test
    void import_secondImportReplaces() throws Exception {
        handler.importCert(new X509ImportRequest(der("tls-client-ok.pem")));
        byte[] second = der("no-eku.pem");

        X509ImportResponse response = handler.importCert(new X509ImportRequest(second));

        assertEquals(Verdict.ACCEPTED, response.verdict());
        assertTrue(response.stored());
        assertArrayEquals(second, storedCert().orElseThrow());
        assertEquals(1, store.keysByProtocol(1240).size(), "replaced, not appended");
    }

    @Test
    void import_keepsOtherMetadata() throws Exception {
        store.addKey(aliceEntry());
        handler.importCert(new X509ImportRequest(der("tls-client-ok.pem")));

        assertEquals("alice@atlanta.com",
                store.getKey(aliceEntry().path()).metadata().get("identity"));
    }

    @Test
    void import_keyMismatchLeavesSlotUnchanged() throws Exception {
        byte[] original = der("tls-client-ok.pem");
        handler.importCert(new X509ImportRequest(original));

        X509ImportResponse response = handler.importCert(new X509ImportRequest(der("different-key.pem")));

        assertEquals(Verdict.KEY_MISMATCH, response.verdict());
        assertFalse(response.stored());
        assertArrayEquals(original, storedCert().orElseThrow());
    }

    @Test
    void import_ekuMismatchLeavesSlotUnchanged() throws Exception {
        byte[] original = der("tls-client-ok.pem");
        handler.importCert(new X509ImportRequest(original));

        X509ImportResponse response = handler.importCert(new X509ImportRequest(der("server-auth.pem")));

        assertEquals(Verdict.EKU_MISMATCH, response.verdict());
        assertFalse(response.stored());
        assertArrayEquals(original, storedCert().orElseThrow());
    }

    @Test
    void import_mismatchOnEmptySlotStoresNothing() throws Exception {
        handler.importCert(new X509ImportRequest(der("client-and-email.pem")));
        assertTrue(storedCert().isEmpty());
    }

    @Test
    void import_malformed() {
        X509ImportResponse response = handler.importCert(new X509ImportRequest(new byte[]{0x30, 0x03, 1}));

        assertEquals(Verdict.MALFORMED, response.verdict());
        assertFalse(response.stored());
        assertTrue(storedCert().isEmpty());
    }

    @Test
    void import_noKeyMatches_otherIdentity() throws Exception {
        // Bob's handler serves no key the certificate carries.
        var bobHandler = new X509ServiceHandler(vault, List.of(BOB), store);
        bobHandler.setApprovalUI((m, d) -> true);

        X509ImportResponse response = bobHandler.importCert(new X509ImportRequest(der("tls-client-ok.pem")));

        assertEquals(Verdict.KEY_MISMATCH, response.verdict());
        assertFalse(response.stored());
        assertTrue(store.allKeys().isEmpty());
    }

    @Test
    void import_matchesTheRightIdentity() throws Exception {
        // Two identities served: the certificate lands in Alice's slot only.
        var both = new X509ServiceHandler(vault, List.of(BOB, ALICE), store);
        both.setApprovalUI((m, d) -> true);

        assertTrue(both.importCert(new X509ImportRequest(der("tls-client-ok.pem"))).stored());
        assertEquals(1, store.allKeys().size());
        assertTrue(storedCert().isPresent());
    }

    @Test
    void import_wireShape_verdictIsAResult() throws Exception {
        JsonObject params = new JsonObject();
        params.addProperty("der", Base64.getEncoder().encodeToString(der("server-auth.pem")));

        JsonObject response = dispatch("import", params);
        assertFalse(response.has("error"));
        JsonObject result = response.getAsJsonObject("result");
        assertEquals("EKU_MISMATCH", result.get("verdict").getAsString());
        assertFalse(result.get("stored").getAsBoolean());
    }

    @Test
    void import_unsupportedWithoutStore() throws Exception {
        var noStore = new X509ServiceHandler(vault, List.of(ALICE), null);
        noStore.setApprovalUI((m, d) -> true);

        var e = assertThrows(IllegalArgumentException.class,
                () -> noStore.importCert(new X509ImportRequest(der("tls-client-ok.pem"))));
        assertEquals("unsupported", e.getMessage());
        assertNull(noStore.list().keys().get(0).cert(), "list still works without a store");
    }

    @Test
    void import_deniedWithoutUI() throws Exception {
        handler.setApprovalUI(null);
        assertThrows(RequestDeniedException.class,
                () -> handler.importCert(new X509ImportRequest(der("tls-client-ok.pem"))));
        assertTrue(storedCert().isEmpty());
    }

    @Test
    void import_deniedWireMessage() throws Exception {
        handler.setApprovalUI(null);
        JsonObject params = new JsonObject();
        params.addProperty("der", Base64.getEncoder().encodeToString(der("tls-client-ok.pem")));

        assertEquals("request denied by user", dispatch("import", params).get("error").getAsString());
    }

    // ── isolation at the channel ──────────────────────────────────────────

    @Test
    void channel_bindsExactlyTheThreeMethods() {
        ServiceChannel channel = new ServiceChannel(handler, ServiceChannel.createGson());
        assertEquals(3, channel.bindingCount());
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private JsonObject dispatch(String method, JsonObject params) {
        JsonArray array = new JsonArray();
        array.add(params);
        Gson gson = ServiceChannel.createGson();
        return new ServiceChannel(handler, gson).dispatch(method, array);
    }

    private Optional<byte[]> storedCert() {
        KeyEntry entry = store.getKey(aliceEntry().path());
        return entry == null ? Optional.empty() : X509CertSlot.get(entry);
    }

    private static KeyEntry aliceEntry() {
        return new KeyEntry(IdentityPaths.hdPath(IdentityPaths.x509(ALICE, X509Role.TLS_CLIENT)),
                java.util.Map.of("identity", ALICE.name()));
    }

    private static byte[] fixture(String name) throws IOException {
        try (InputStream in = X509ServiceHandlerTest.class.getResourceAsStream("/x509/" + name)) {
            assertNotNull(in, "missing fixture " + name);
            return in.readAllBytes();
        }
    }

    /** A PEM fixture as DER, via the JDK parser. */
    private static byte[] der(String name) throws Exception {
        return CertificateFactory.getInstance("X.509", "SUN")
                .generateCertificate(new ByteArrayInputStream(fixture(name)))
                .getEncoded();
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    /** Raw 64-byte r || s to a DER ECDSA-Sig-Value: SEQUENCE { INTEGER r, INTEGER s }. */
    static byte[] rawToDer(byte[] rs) {
        byte[] r = new BigInteger(1, Arrays.copyOfRange(rs, 0, 32)).toByteArray();
        byte[] s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64)).toByteArray();
        byte[] out = new byte[6 + r.length + s.length];
        int i = 0;
        out[i++] = 0x30;
        out[i++] = (byte) (4 + r.length + s.length); // < 128: short-form length
        out[i++] = 0x02;
        out[i++] = (byte) r.length;
        System.arraycopy(r, 0, out, i, r.length);
        i += r.length;
        out[i++] = 0x02;
        out[i++] = (byte) s.length;
        System.arraycopy(s, 0, out, i, s.length);
        return out;
    }
}
