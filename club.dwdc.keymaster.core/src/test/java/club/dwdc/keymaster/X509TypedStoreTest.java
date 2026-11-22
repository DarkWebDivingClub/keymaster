package club.dwdc.keymaster;

import club.dwdc.keymaster.X509CertCheck.Verdict;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.Protocol;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.bitcoinj.crypto.HDPath;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Mission 50: certificates in the typed store ({@link X509KeyEntry},
 * {@link KVX509CertStore}) and the reserved {@code chain} field.
 */
class X509TypedStoreTest {

    private static final Identity ALICE = new Identity("alice@atlanta.com");
    private static final HDPath ALICE_TLS =
            IdentityPaths.hdPath(IdentityPaths.x509(ALICE, X509Role.TLS_CLIENT));

    private static Bip32KeyVault vault;

    @BeforeAll
    static void setUpVault() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        vault = new Bip32KeyVault(RealmTest.TEST_MNEMONIC);
    }

    // ── X509KeyEntry ──────────────────────────────────────────────────────

    @Test
    void entry_withoutCertificate() {
        var entry = new X509KeyEntry(ALICE_TLS, ALICE.name());

        assertTrue(entry.certificate().isEmpty());
        assertEquals(Protocol.X509.coinType(), entry.coinType());
        assertEquals(X509Role.TLS_CLIENT.number(), entry.role());
        assertEquals(ALICE.name(), entry.toKeyEntry().metadata().get("identity"));
        assertFalse(entry.toKeyEntry().metadata().containsKey(X509CertSlot.KEY));
    }

    @Test
    void entry_withCertificateReplacesAndCopies() {
        byte[] first = {1, 2, 3};
        byte[] second = {4, 5};
        var entry = new X509KeyEntry(ALICE_TLS, ALICE.name()).withCertificate(first);
        var replaced = entry.withCertificate(second);

        assertArrayEquals(first, entry.certificate().orElseThrow(), "the original is unchanged");
        assertArrayEquals(second, replaced.certificate().orElseThrow());
        assertEquals(entry, replaced, "same path, same entry");

        first[0] = 9;
        assertEquals(1, entry.certificate().orElseThrow()[0], "the entry keeps its own copy");
        entry.certificate().orElseThrow()[0] = 9;
        assertEquals(1, entry.certificate().orElseThrow()[0], "callers get a copy");
    }

    @Test
    void entry_toKeyEntryWritesTheCertSlot() {
        byte[] der = {0x30, 0x03, 0x02, 0x01, 0x01};
        KeyEntry generic = new X509KeyEntry(ALICE_TLS, ALICE.name(), der).toKeyEntry();

        assertArrayEquals(der, X509CertSlot.get(generic).orElseThrow());
    }

    // ── the handler over the typed store ──────────────────────────────────

    @Test
    void kvStore_importIsStoredAsX509KeyEntryAndListed() throws Exception {
        var store = new InMemoryKVMetaStore();
        var handler = handler(X509CertStore.of(store));
        byte[] der = der("tls-client-ok.pem");

        X509ImportResponse response = handler.importCert(new X509ImportRequest(der));

        assertEquals(Verdict.ACCEPTED, response.verdict());
        assertTrue(response.stored());
        var entry = assertInstanceOf(X509KeyEntry.class, store.get(ALICE_TLS));
        assertEquals(ALICE.name(), entry.identity());
        assertArrayEquals(der, entry.certificate().orElseThrow());
        assertArrayEquals(der, handler.list().keys().get(0).cert());
    }

    @Test
    void kvStore_secondImportReplaces() throws Exception {
        var store = new InMemoryKVMetaStore();
        var handler = handler(X509CertStore.of(store));
        handler.importCert(new X509ImportRequest(der("tls-client-ok.pem")));
        byte[] second = der("no-eku.pem");

        assertTrue(handler.importCert(new X509ImportRequest(second)).stored());

        assertEquals(1, store.byType(X509KeyEntry.class).size(), "replaced, not appended");
        assertArrayEquals(second, handler.list().keys().get(0).cert());
    }

    @Test
    void kvStore_rejectedImportLeavesTheCertificate() throws Exception {
        var store = new InMemoryKVMetaStore();
        var handler = handler(X509CertStore.of(store));
        byte[] original = der("tls-client-ok.pem");
        handler.importCert(new X509ImportRequest(original));

        assertFalse(handler.importCert(new X509ImportRequest(der("server-auth.pem"))).stored());
        assertArrayEquals(original, handler.list().keys().get(0).cert());
    }

    @Test
    void kvStore_replacesAnEntryOfAnotherTypeAtTheX509Path() throws Exception {
        // 0.6.1 and earlier read X.509 entries back as SSH.
        var store = new InMemoryKVMetaStore();
        store.put(new SSHKeyEntry(ALICE_TLS, ALICE.name(), ALICE.name()));
        var handler = handler(X509CertStore.of(store));

        assertTrue(handler.importCert(new X509ImportRequest(der("tls-client-ok.pem"))).stored());
        assertInstanceOf(X509KeyEntry.class, store.get(ALICE_TLS));
    }

    @Test
    void kvStore_listWithoutCertificate() {
        var store = new InMemoryKVMetaStore();
        store.put(new X509KeyEntry(ALICE_TLS, ALICE.name()));

        assertNull(handler(X509CertStore.of(store)).list().keys().get(0).cert());
    }

    // ── the reserved chain ────────────────────────────────────────────────

    @Test
    void chain_isRefusedUnsupportedAndNothingIsStored() throws Exception {
        var store = new InMemoryKVMetaStore();
        var handler = handler(X509CertStore.of(store));
        List<String> asked = new java.util.ArrayList<>();
        handler.setApprovalUI((m, d) -> asked.add(m));

        var e = assertThrows(IllegalArgumentException.class, () -> handler.importCert(
                new X509ImportRequest(der("tls-client-ok.pem"), List.of(der("tls-client-ok.pem")))));

        assertEquals("unsupported", e.getMessage());
        assertTrue(asked.isEmpty(), "refused before the user is asked");
        assertNull(store.get(ALICE_TLS));
    }

    @Test
    void chain_onTheWireIsAnUnsupportedError() throws Exception {
        var handler = handler(X509CertStore.of(new InMemoryKVMetaStore()));
        String b64 = Base64.getEncoder().encodeToString(der("tls-client-ok.pem"));
        JsonObject params = new JsonObject();
        params.addProperty("der", b64);
        JsonArray chain = new JsonArray();
        chain.add(b64);
        params.add("chain", chain);
        JsonArray args = new JsonArray();
        args.add(params);

        JsonObject response = new ServiceChannel(handler, ServiceChannel.createGson()).dispatch("import", args);

        assertEquals("unsupported", response.get("error").getAsString());
    }

    @Test
    void chain_absentOnTheWireIsTheCertificateOnly() throws Exception {
        var handler = handler(X509CertStore.of(new InMemoryKVMetaStore()));
        JsonObject params = new JsonObject();
        params.addProperty("der", Base64.getEncoder().encodeToString(der("tls-client-ok.pem")));
        JsonArray args = new JsonArray();
        args.add(params);

        JsonObject response = new ServiceChannel(handler, ServiceChannel.createGson()).dispatch("import", args);

        assertTrue(response.getAsJsonObject("result").get("stored").getAsBoolean());
    }

    // ── the controller on the typed store (Android) ───────────────────────

    @Test
    void controller_createIdentityAddsX509Entries() {
        var store = new InMemoryKVMetaStore();
        var ctrl = new KeyMasterController(new KeyMaster(vault, store));
        ctrl.createIdentity(ALICE.name(), "Alice", ALICE.name());

        List<X509KeyEntry> x509 = store.byType(X509KeyEntry.class);
        assertEquals(1, x509.size(), "TLS client only");
        assertEquals(ALICE_TLS, x509.get(0).path());
        assertTrue(x509.get(0).certificate().isEmpty());
    }

    @Test
    void controller_createIdentityKeepsAStoredCertificate() {
        var store = new InMemoryKVMetaStore();
        byte[] der = {0x30, 0x03, 0x02, 0x01, 0x01};
        store.put(new X509KeyEntry(ALICE_TLS, ALICE.name(), der));
        new KeyMasterController(new KeyMaster(vault, store))
                .createIdentity(ALICE.name(), "Alice", ALICE.name());

        assertArrayEquals(der, ((X509KeyEntry) store.get(ALICE_TLS)).certificate().orElseThrow());
    }

    @Test
    void controller_realmOnTheTypedStoreAcceptsImport() throws Exception {
        var store = new InMemoryKVMetaStore();
        var ctrl = new KeyMasterController(new KeyMaster(vault, store));
        ctrl.createIdentity(ALICE.name(), "Alice", ALICE.name());
        Realm realm = ctrl.createRealm("phone", ALICE);

        var x509 = (X509ServiceHandler) realm.getHandler(Protocol.X509.coinType());
        x509.setApprovalUI((m, d) -> true);
        assertTrue(x509.importCert(new X509ImportRequest(der("tls-client-ok.pem"))).stored());
        assertTrue(((X509KeyEntry) store.get(ALICE_TLS)).certificate().isPresent());
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private static X509ServiceHandler handler(X509CertStore store) {
        var handler = new X509ServiceHandler(vault, List.of(ALICE), store);
        handler.setApprovalUI((m, d) -> true);
        return handler;
    }

    private static byte[] der(String name) throws Exception {
        try (InputStream in = X509TypedStoreTest.class.getResourceAsStream("/x509/" + name)) {
            assertNotNull(in, "missing fixture " + name);
            return CertificateFactory.getInstance("X.509", "SUN")
                    .generateCertificate(new ByteArrayInputStream(in.readAllBytes()))
                    .getEncoded();
        }
    }
}
