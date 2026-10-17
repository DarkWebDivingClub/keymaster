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
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class RealmTest {

    static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon " +
            "abandon abandon abandon abandon abandon about";

    static KeyEntry sshKeyEntry(String identity) {
        HDPath path = HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.SSH.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
            new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        return new KeyEntry(path, Map.of("comment", identity));
    }

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
                "creation_time", "1700000000",
                "pgp_name", identity,
                "pgp_email", identity));
    }

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

    static KeyEntry mlsKeyEntry(String identity) {
        HDPath path = HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.MLS.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, AlgField.ROLE_SIGN).toIndex(), true),
            new ChildNumber(new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex(), true)
        );
        return new KeyEntry(path, Map.of("identity", identity));
    }

    /** Mirrors what {@code createIdentity} writes: ssh, gpg x2, nostr, mls. */
    static void populateStore(InMemoryKeyMetaDataStore store, String identity) {
        store.addIdentity(identity);
        store.addKey(sshKeyEntry(identity));
        store.addKey(gpgKeyEntry(identity, 0, "certification"));
        store.addKey(gpgKeyEntry(identity, 1, "signing"));
        store.addKey(nostrKeyEntry(identity));
        store.addKey(mlsKeyEntry(identity));
    }

    /** Build a realm the way the controller does: selections resolved against a store. */
    static Realm realm(InMemoryKeyMetaDataStore store, KeyVault vault,
                       Identity primary, IdentitySelection... selections) {
        return new Realm(1234, "myFirstRealm", List.of(selections), primary,
                vault, store.allKeys(), null);
    }

    // ── handler resolution tests ──────────────────────────────────────────

    @Test
    void resolveHandlers_singleIdentity_createsBothHandlers() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");

        var alice = new Identity("alice@atlanta.com");
        var realm = realm(store, vault, alice, new IdentitySelection(alice));

        assertNotNull(realm.getHandler(Protocol.SSH.coinType()));
        assertNotNull(realm.getHandler(Protocol.OPENPGP.coinType()));
        assertEquals(
                Set.of(Protocol.SSH.coinType(), Protocol.OPENPGP.coinType(),
                        Protocol.NOSTR.coinType()),
                realm.getHandlerCoinTypes());
    }

    @Test
    void resolveHandlers_protocolFilter_onlySshHandler() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");

        // Filter to SSH keys only
        var alice = new Identity("alice@atlanta.com");
        var realm = realm(store, vault, alice,
                new IdentitySelection(alice, Set.of(Protocol.SSH.coinType())));

        assertNotNull(realm.getHandler(Protocol.SSH.coinType()));
        assertNull(realm.getHandler(Protocol.OPENPGP.coinType()));
        assertEquals(Set.of(Protocol.SSH.coinType()), realm.getHandlerCoinTypes());
    }

    @Test
    void resolveHandlers_multipleIdentities_handlersContainKeysFromBoth() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");
        populateStore(store, "bob@ssh.com");

        var alice = new Identity("alice@atlanta.com");
        var bob = new Identity("bob@ssh.com");
        var realm = realm(store, vault, alice,
                new IdentitySelection(alice), new IdentitySelection(bob));

        assertNotNull(realm.getHandler(Protocol.SSH.coinType()));
        assertNotNull(realm.getHandler(Protocol.OPENPGP.coinType()));
        assertEquals(
                Set.of(Protocol.SSH.coinType(), Protocol.OPENPGP.coinType(),
                        Protocol.NOSTR.coinType()),
                realm.getHandlerCoinTypes());
    }

    @Test
    void resolveHandlers_allKeys_allCoinTypesPresent() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");

        var alice = new Identity("alice@atlanta.com");
        var realm = realm(store, vault, alice, new IdentitySelection(alice));

        assertTrue(realm.getHandlerCoinTypes().contains(Protocol.SSH.coinType()));
        assertTrue(realm.getHandlerCoinTypes().contains(Protocol.OPENPGP.coinType()));
    }

    // ── getHandler tests ──────────────────────────────────────────────────

    @Test
    void getHandler_returnsCorrectHandlerByCoinType() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");

        var alice = new Identity("alice@atlanta.com");
        var realm = realm(store, vault, alice, new IdentitySelection(alice));

        assertInstanceOf(SshServiceHandler.class, realm.getHandler(Protocol.SSH.coinType()));
        assertInstanceOf(GpgServiceHandler.class, realm.getHandler(Protocol.OPENPGP.coinType()));
    }

    @Test
    void getHandler_returnsNullForUnknownCoinType() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");

        var alice = new Identity("alice@atlanta.com");
        var realm = realm(store, vault, alice, new IdentitySelection(alice));

        assertNull(realm.getHandler(99999));
    }

    // ── putHandler tests ──────────────────────────────────────────────────

    @Test
    void putHandler_setsHandler() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var realm = new Realm(1, "direct", new Identity("alice@atlanta.com"), vault);
        var handler = new SshServiceHandler(vault, List.of(sshKeyEntry("alice@atlanta.com")));

        realm.putHandler(Protocol.SSH.coinType(), handler);

        assertSame(handler, realm.getHandler(Protocol.SSH.coinType()));
    }

    @Test
    void putHandler_replacesExistingHandler() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var realm = new Realm(1, "direct", new Identity("alice@atlanta.com"), vault);
        var first = new SshServiceHandler(vault, List.of(sshKeyEntry("alice@atlanta.com")));
        var second = new SshServiceHandler(vault, List.of(sshKeyEntry("bob@ssh.com")));

        realm.putHandler(Protocol.SSH.coinType(), first);
        realm.putHandler(Protocol.SSH.coinType(), second);

        assertSame(second, realm.getHandler(Protocol.SSH.coinType()));
    }

    @Test
    void getHandlerCoinTypes_reflectsPuts() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var realm = new Realm(1, "direct", new Identity("alice@atlanta.com"), vault);

        assertTrue(realm.getHandlerCoinTypes().isEmpty());

        realm.putHandler(Protocol.SSH.coinType(),
                new SshServiceHandler(vault, List.of(sshKeyEntry("alice@atlanta.com"))));
        realm.putHandler(Protocol.OPENPGP.coinType(),
                new GpgServiceHandler(vault, List.of()));

        assertEquals(
                Set.of(Protocol.SSH.coinType(), Protocol.OPENPGP.coinType()),
                realm.getHandlerCoinTypes());
    }

    // ── definition and invariants ─────────────────────────────────────────

    @Test
    void primaryIdentityNotAmongSelections_rejected() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");

        var alice = new Identity("alice@atlanta.com");
        var stranger = new Identity("eve@elsewhere.net");

        var e = assertThrows(IllegalArgumentException.class, () ->
                new Realm(1234, "myFirstRealm", List.of(new IdentitySelection(alice)),
                        stranger, vault, store.allKeys(), null));
        assertTrue(e.getMessage().contains("not among the realm's selections"));
    }

    @Test
    void mangleCollisionBetweenSelections_rejected() {
        // A real collision in mangle()'s 31-bit space, found by search and
        // pinned here: both names hash to 465816612. Two identities sharing a
        // path index would merge their scopes and void each other's protocol
        // filters, so the realm refuses to resolve.
        var one = new Identity("c71864@t.io");
        var two = new Identity("c100447@t.io");
        assertEquals(one.mangled(), two.mangled(), "test fixture must collide");

        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, one.name());

        var e = assertThrows(IllegalArgumentException.class, () ->
                new Realm(1234, "collides",
                        List.of(new IdentitySelection(one), new IdentitySelection(two)),
                        one, vault, store.allKeys(), null));
        assertTrue(e.getMessage().contains("mangle collision"));
    }

    @Test
    void sameIdentityTwice_accepted() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");
        var alice = new Identity("alice@atlanta.com");

        var realm = realm(store, vault, alice,
                new IdentitySelection(alice), new IdentitySelection(alice));

        assertEquals(List.of("alice@atlanta.com"), realm.identityNames());
    }

    @Test
    void identityFor_resolvesServedIdentitiesOnly() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");
        populateStore(store, "alice@home.org");

        var atlanta = new Identity("alice@atlanta.com");
        var home = new Identity("alice@home.org");
        var realm = realm(store, vault, atlanta, new IdentitySelection(atlanta));

        assertEquals(atlanta, realm.identityFor(atlanta.mangled()).orElseThrow());
        assertTrue(realm.identityFor(home.mangled()).isEmpty(),
                "a realm must not name an identity it does not serve");
    }

    @Test
    void perIdentityProtocolFilter_servesOnlySelectedProtocols() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");
        populateStore(store, "alice@home.org");

        var atlanta = new Identity("alice@atlanta.com");
        var home = new Identity("alice@home.org");

        // atlanta: everything. home.org: ssh only.
        var realm = realm(store, vault, atlanta,
                new IdentitySelection(atlanta),
                new IdentitySelection(home, Set.of(Protocol.SSH.coinType())));

        assertEquals(List.of("alice@atlanta.com", "alice@home.org"), realm.identityNames());

        assertEquals(2, realm.getHandler(Protocol.SSH.coinType()).keys().size(),
                "both identities contribute their SSH key");
        assertEquals(2, realm.getHandler(Protocol.OPENPGP.coinType()).keys().size(),
                "only atlanta's certification and signing keys");
        assertEquals(1, realm.getHandler(Protocol.NOSTR.coinType()).keys().size(),
                "only atlanta's nostr key");

        int homeMangled = home.mangled();
        assertTrue(realm.getHandler(Protocol.OPENPGP.coinType()).keys().stream()
                        .noneMatch(k -> k.identity() == homeMangled),
                "home.org contributed nothing but its SSH key");
        assertTrue(realm.getHandler(Protocol.NOSTR.coinType()).keys().stream()
                        .noneMatch(k -> k.identity() == homeMangled));

        assertFalse(realm.getHandlerCoinTypes().contains(Protocol.MLS.coinType()),
                "MLS is served by the nostr handler, not as a handler of its own");
    }

    @Test
    void blankName_defaultsToPrimaryLocalPart() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");
        var alice = new Identity("alice@atlanta.com");

        var realm = new Realm(1234, "  ", List.of(new IdentitySelection(alice)),
                alice, vault, store.allKeys(), null);

        assertEquals("alice", realm.name());
    }

    @Test
    void rename_doesNotChangeAnyDerivedPath() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");
        var alice = new Identity("alice@atlanta.com");
        var realm = realm(store, vault, alice, new IdentitySelection(alice));

        int[] before = realm.primaryNostrPath();
        realm.setName("something else entirely");

        assertArrayEquals(before, realm.primaryNostrPath());
        assertEquals(1234, realm.id());
    }

    // ── paths ─────────────────────────────────────────────────────────────

    @Test
    void primaryNostrPath_matchesTheStoredNostrEntry() {
        // The realm builds this path itself while createIdentity stores an entry
        // at the same place. Nothing else makes the two agree, and a drift in
        // the alg or config level would be a wrong-key bug no other test sees.
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");
        var alice = new Identity("alice@atlanta.com");
        var realm = realm(store, vault, alice, new IdentitySelection(alice));

        KeyEntry stored = store.allKeys().stream()
                .filter(k -> k.coinType() == Protocol.NOSTR.coinType()
                        && k.identity() == alice.mangled())
                .findFirst()
                .orElseThrow();

        assertArrayEquals(stored.toVaultPath(), realm.primaryNostrPath());
    }

    @Test
    void primaryNostrPath_isTheIdentityNostrKey() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        populateStore(store, "alice@atlanta.com");
        var alice = new Identity("alice@atlanta.com");
        var realm = realm(store, vault, alice, new IdentitySelection(alice));

        int[] path = realm.primaryNostrPath();

        assertEquals(5, path.length);
        assertEquals(44, path[0] & 0x7FFFFFFF);
        assertEquals(Protocol.NOSTR.coinType(), path[1] & 0x7FFFFFFF);
        assertEquals(alice.mangled(), path[2] & 0x7FFFFFFF);
    }

    @Test
    void identityKeys_unchangedByTheRefactor() {
        // Golden values: the identity trees are frozen, so these must never
        // move. See doc/key-derivation.md.
        var vault = new Bip32KeyVault(TEST_MNEMONIC);

        assertEquals(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHeeTgJw+7G4gFYEZPDvW9bbMApCD+5Pdeq1butlUfjQ"
                        + " alice@atlanta.com",
                SshServiceHandler.getAuthorizedKeysLine(vault, "alice@atlanta.com"));

        int H = 0x80000000;
        int[] nostrPath = {
                44 | H,
                Protocol.NOSTR.coinType() | H,
                new Identity("alice@atlanta.com").mangled() | H,
                new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };
        byte[] compressed = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, nostrPath).data();
        assertEquals("fa7851825be694a747ec9d93ea0b46be6f36a40af6ec3c5b2682d1dafe59dd12",
                nostr.util.NostrUtil.bytesToHex(
                        java.util.Arrays.copyOfRange(compressed, 1, 33)));
    }

    // ── the handshake key comes from the store (F2) ───────────────────────

    @Test
    void primaryWithoutAStoredNostrKey_isRefused() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        var alice = new Identity("alice@atlanta.com");
        store.addIdentity(alice.name());
        store.addKey(sshKeyEntry(alice.name()));
        store.addKey(gpgKeyEntry(alice.name(), 0, "certification"));
        // deliberately no nostr entry

        var e = assertThrows(IllegalArgumentException.class, () ->
                realm(store, vault, alice, new IdentitySelection(alice)));
        assertTrue(e.getMessage().contains("has no Nostr key"), e.getMessage());
        assertTrue(e.getMessage().contains(alice.name()), "the message must name the identity");
    }

    @Test
    void theInvariantBindsThePrimaryOnly() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        var alice = new Identity("alice@atlanta.com");
        var bob = new Identity("bob@ssh.com");
        populateStore(store, alice.name());
        store.addIdentity(bob.name());
        store.addKey(sshKeyEntry(bob.name()));   // bob has ssh only, no nostr

        var realm = realm(store, vault, alice,
                new IdentitySelection(alice),
                new IdentitySelection(bob, Set.of(Protocol.SSH.coinType())));

        assertEquals(2, realm.getHandler(Protocol.SSH.coinType()).keys().size());
        assertEquals(List.of("alice@atlanta.com", "bob@ssh.com"), realm.identityNames());
    }

    @Test
    void theInvariantIsCheckedAgainstTheUnfilteredStore() {
        // A realm may serve no Nostr key at all and still sign its handshake
        // with one — the filter governs what is served, never whether login
        // is possible.
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        var alice = new Identity("alice@atlanta.com");
        populateStore(store, alice.name());

        var realm = realm(store, vault, alice,
                new IdentitySelection(alice, Set.of(Protocol.SSH.coinType())));

        assertNull(realm.getHandler(Protocol.NOSTR.coinType()), "nostr is not served");
        assertArrayEquals(IdentityPaths.nostr(alice), realm.primaryNostrPath(),
                "yet the handshake key is still alice's nostr key");
    }

    // ── a failed attach leaves nothing behind (36.3.4 F5) ─────────────────

    @Test
    void failedAttach_leavesNoConnector() {
        var vault = new Bip32KeyVault(TEST_MNEMONIC);
        var store = new InMemoryKeyMetaDataStore();
        var alice = new Identity("alice@atlanta.com");
        populateStore(store, alice.name());
        var realm = realm(store, vault, alice, new IdentitySelection(alice));

        realm.setRelayClientFactory(descriptor -> {
            throw new IllegalStateException("relay unavailable");
        });

        var descriptor = new AvatarDescriptor(
                "ws://127.0.0.1:1", "xpub6CUGRUonZSQ4TWtTMmzXdrXDtyPWKiKbbqnWxx2qaGvxZ2x",
                List.of("ssh"));

        assertThrows(Exception.class, () -> realm.attach(descriptor));
        assertTrue(realm.connectorIds().isEmpty(), "the reservation must be rolled back");
        assertFalse(realm.hasConnectors());

        // and the realm is still usable afterwards
        assertNotNull(realm.getHandler(Protocol.SSH.coinType()));
    }

    // ── per-connector state (36.3.6) ──────────────────────────────────────

    @Test
    void theForwarderNamesTheConnectorAndStillTellsTheRealm() {
        var realm = singleIdentityRealm();
        var perConnector = new java.util.ArrayList<String>();
        var perRealm = new java.util.ArrayList<NostrTransport.ConnectionState>();
        realm.setConnectorStateListener((id, state) -> perConnector.add(id + ":" + state));
        realm.setConnectionStateListener(perRealm::add);

        realm.stateForwarder(111).accept(NostrTransport.ConnectionState.CONNECTED);
        realm.stateForwarder(222).accept(NostrTransport.ConnectionState.RETRYING);

        assertEquals(List.of("111:CONNECTED", "222:RETRYING"), perConnector,
                "a row per avatar needs the id, not just the state");
        assertEquals(List.of(NostrTransport.ConnectionState.CONNECTED,
                NostrTransport.ConnectionState.RETRYING), perRealm,
                "the realm-wide listener is unaffected");
    }

    @Test
    void aListenerInstalledAfterAttachStillReceives() {
        // The service attaches first and wires the UI afterwards, so the
        // forwarder must read the field at call time, not capture it.
        var realm = singleIdentityRealm();
        var forwarder = realm.stateForwarder(7);
        forwarder.accept(NostrTransport.ConnectionState.CONNECTED);   // nobody listening

        var seen = new java.util.ArrayList<String>();
        realm.setConnectorStateListener((id, state) -> seen.add(id + ":" + state));
        forwarder.accept(NostrTransport.ConnectionState.DISCONNECTED);

        assertEquals(List.of("7:DISCONNECTED"), seen);
    }

    @Test
    void noListenerIsNotAnError() {
        var realm = singleIdentityRealm();
        assertDoesNotThrow(() ->
                realm.stateForwarder(1).accept(NostrTransport.ConnectionState.RETRYING));

        realm.setConnectorStateListener((id, state) -> { });
        realm.setConnectorStateListener(null);
        assertDoesNotThrow(() ->
                realm.stateForwarder(1).accept(NostrTransport.ConnectionState.CONNECTED));
    }

    private Realm singleIdentityRealm() {
        var store = new InMemoryKeyMetaDataStore();
        var alice = new Identity("alice@atlanta.com");
        populateStore(store, alice.name());
        return realm(store, new Bip32KeyVault(TEST_MNEMONIC), alice,
                new IdentitySelection(alice));
    }
}
