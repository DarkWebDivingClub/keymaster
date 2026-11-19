package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.KeyVault;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Golden values straight out of {@code doc/key-derivation.md}.
 *
 * <p>The document's worked example is `alice@atlanta.com`, whose mangle is
 * 1955269225. Asserting it literally is the point: the document and this class
 * are two statements of the same layout, and they should fail together or not
 * at all.
 */
class IdentityPathsTest {

    private static final int H = 0x80000000;
    private static final Identity ALICE = new Identity("alice@atlanta.com");
    private static final int MANGLE = 1955269225;

    private static int[] p(int... levels) {
        return levels;
    }

    @Test
    void theDocumentsMangleStillHolds() {
        assertEquals(MANGLE, ALICE.mangled());
        assertEquals(MANGLE, Bip32KeyDerivator.mangle("alice@atlanta.com"));
    }

    @Test
    void sshMatchesTheDocument() {   // m/44'/1238'/1955269225'/0'/0' (65536' before 0.9.0)
        assertArrayEquals(p(44 | H, 1238 | H, MANGLE | H, 0 | H, 0 | H),
                IdentityPaths.ssh(ALICE));
    }

    @Test
    void gpgMatchesTheDocument() {   // 0' certification, 1' signing (65536'/65537' before 0.9.0)
        assertArrayEquals(p(44 | H, 1239 | H, MANGLE | H, 0 | H, 0 | H),
                IdentityPaths.gpg(ALICE, IdentityPaths.OPENPGP_CERTIFICATION));
        assertArrayEquals(p(44 | H, 1239 | H, MANGLE | H, 1 | H, 0 | H),
                IdentityPaths.gpg(ALICE, IdentityPaths.OPENPGP_SIGNING));
    }

    @Test
    void nostrMatchesTheDocument() {   // m/44'/1237'/1955269225'/0'/0'
        assertArrayEquals(p(44 | H, 1237 | H, MANGLE | H, 0 | H, 0 | H),
                IdentityPaths.nostr(ALICE));
    }

    @Test
    void mlsSignMatchesTheDocument() {   // m/44'/1242'/1955269225'/0'/0' (65536' before 0.9.0)
        assertArrayEquals(p(44 | H, 1242 | H, MANGLE | H, 0 | H, 0 | H),
                IdentityPaths.mlsSign(ALICE));
    }

    @Test
    void x509TlsClientMatchesTheMission() {   // m/44'/1240'/1955269225'/2'/0'
        // use' = UseField(0, tls-client 2). Before 0.9.0: 196866 = ALG_ECDSA(3) << 16 | P-256(1) << 8 | 2
        assertArrayEquals(p(44 | H, 1240 | H, MANGLE | H, 2 | H, 0 | H),
                IdentityPaths.x509(ALICE, X509Role.TLS_CLIENT));
    }

    @Test
    void x509LabelIsGenerated() {
        assertEquals("alice@atlanta.com tls-client",
                IdentityPaths.x509Label(ALICE, X509Role.TLS_CLIENT));
    }

    @Test
    void x509LabelSurvivesPercentEncoding() {
        String label = IdentityPaths.x509Label(ALICE, X509Role.TLS_CLIENT);

        // RFC 7512 lets '@' appear literally or as %40; a space must be %20.
        for (boolean encodeAt : new boolean[]{false, true}) {
            String encoded = pk11Encode(label, encodeAt);

            assertTrue(encoded.equals("alice@atlanta.com%20tls-client")
                    || encoded.equals("alice%40atlanta.com%20tls-client"), encoded);
            assertFalse(encoded.contains(" "), "space must be encoded");
            assertTrue(encoded.endsWith("%20tls-client"), "role token must be intact");
            assertEquals(label, pk11Decode(encoded));
        }
    }

    /** Minimal RFC 7512 attribute-value encoder: unreserved chars stay, the rest is %XX. */
    private static String pk11Encode(String value, boolean encodeAt) {
        StringBuilder out = new StringBuilder();
        for (byte b : value.getBytes(java.nio.charset.StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xFF);
            boolean unreserved = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~';
            if (unreserved || (c == '@' && !encodeAt)) {
                out.append(c);
            } else {
                out.append(String.format("%%%02X", b & 0xFF));
            }
        }
        return out.toString();
    }

    /** Inverse of {@link #pk11Encode}. */
    private static String pk11Decode(String encoded) {
        var bytes = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < encoded.length(); i++) {
            char c = encoded.charAt(i);
            if (c == '%') {
                bytes.write(Integer.parseInt(encoded.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                bytes.write(c);
            }
        }
        return bytes.toString(java.nio.charset.StandardCharsets.UTF_8);
    }

    @Test
    void mlsHpkeVariesOnlyInItsConfigIndex() {
        int[] first = IdentityPaths.mlsHpke(ALICE, 0);
        int[] second = IdentityPaths.mlsHpke(ALICE, 1);

        assertEquals(1242, first[1] & ~H);
        assertEquals(IdentityPaths.MLS_HPKE, first[3] & ~H, "MLS HPKE role 1 (65537 before 0.9.0)");
        for (int level = 0; level < 4; level++) {
            assertEquals(first[level], second[level], "only the index may differ");
        }
        assertNotEquals(first[4], second[4]);
    }

    @Test
    void theMangledVariantsAgreeWithTheIdentityOnes() {
        assertArrayEquals(IdentityPaths.mlsSign(ALICE), IdentityPaths.mlsSignFor(MANGLE));
        assertArrayEquals(IdentityPaths.mlsHpke(ALICE, 3), IdentityPaths.mlsHpkeFor(MANGLE, 3));
    }

    @Test
    void everyIdentityLevelIsHardened() {
        for (int[] path : new int[][]{
                IdentityPaths.nostr(ALICE), IdentityPaths.ssh(ALICE),
                IdentityPaths.gpg(ALICE, 0), IdentityPaths.mlsSign(ALICE),
                IdentityPaths.mlsHpke(ALICE, 7)}) {
            assertEquals(5, path.length);
            for (int level : path) {
                assertTrue((level & H) != 0, "identity paths are hardened throughout");
            }
        }
    }

    @Test
    void hdPathRoundTripsAndKeepsHardening() {
        int[] path = IdentityPaths.gpg(ALICE, 1);
        var hd = IdentityPaths.hdPath(path);

        assertEquals(5, hd.size());
        for (int i = 0; i < path.length; i++) {
            assertEquals(path[i] & ~H, hd.get(i).num());
            assertTrue(hd.get(i).isHardened());
        }
    }

    @Test
    void theVaultAcceptsEveryIdentityPath() {
        var vault = new Bip32KeyVault(RealmTest.TEST_MNEMONIC);
        for (int[] path : new int[][]{
                IdentityPaths.nostr(ALICE), IdentityPaths.ssh(ALICE),
                IdentityPaths.gpg(ALICE, 0), IdentityPaths.gpg(ALICE, 1),
                IdentityPaths.mlsSign(ALICE), IdentityPaths.mlsHpke(ALICE, 0)}) {
            assertTrue(vault.execute(IdentityPaths.algFor(path[1] & ~H), KeyVault.FN_GET_PUBLIC_KEY, 0, null, path).isOk(),
                    "vault rejected a path this class produced");
        }
    }

    @Test
    void algorithmPerProtocol() {
        assertEquals(club.dwdc.keyvault.core.Alg.SECP256K1, IdentityPaths.algFor(1237));
        assertEquals(club.dwdc.keyvault.core.Alg.ED25519, IdentityPaths.algFor(1238));
        assertEquals(club.dwdc.keyvault.core.Alg.ED25519, IdentityPaths.algFor(1239));
        assertEquals(club.dwdc.keyvault.core.Alg.P256, IdentityPaths.algFor(1240));
        assertEquals(club.dwdc.keyvault.core.Alg.ED25519, IdentityPaths.algFor(1242));
        assertEquals(club.dwdc.keyvault.core.Alg.SECP256K1, IdentityPaths.algFor(RealmPaths.KM_PURPOSE));
    }

    @Test
    void x509RolesAreFrozen() {
        assertEquals(0, X509Role.CA.number());
        assertEquals(1, X509Role.TLS_SERVER.number());
        assertEquals(2, X509Role.TLS_CLIENT.number());
        assertEquals(3, X509Role.CODE_SIGNING.number());
        assertEquals(4, X509Role.SMIME.number());
        assertEquals(5, X509Role.SMIME_ENCRYPT.number());
        assertEquals("smime-encrypt", X509Role.SMIME_ENCRYPT.token());
        assertEquals(java.util.List.of(X509Role.TLS_CLIENT), X509Role.TEMPLATE, "smime-encrypt is not in the template");
    }
}
