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
    void sshMatchesTheDocument() {   // m/44'/1238'/1955269225'/65536'/0'
        assertArrayEquals(p(44 | H, 1238 | H, MANGLE | H, 65536 | H, 0 | H),
                IdentityPaths.ssh(ALICE));
    }

    @Test
    void gpgMatchesTheDocument() {   // 65536' certification, 65537' signing
        assertArrayEquals(p(44 | H, 1239 | H, MANGLE | H, 65536 | H, 0 | H),
                IdentityPaths.gpg(ALICE, 0));
        assertArrayEquals(p(44 | H, 1239 | H, MANGLE | H, 65537 | H, 0 | H),
                IdentityPaths.gpg(ALICE, 1));
    }

    @Test
    void nostrMatchesTheDocument() {   // m/44'/1237'/1955269225'/0'/0'
        assertArrayEquals(p(44 | H, 1237 | H, MANGLE | H, 0 | H, 0 | H),
                IdentityPaths.nostr(ALICE));
    }

    @Test
    void mlsSignMatchesTheDocument() {   // m/44'/1242'/1955269225'/65536'/0'
        assertArrayEquals(p(44 | H, 1242 | H, MANGLE | H, 65536 | H, 0 | H),
                IdentityPaths.mlsSign(ALICE));
    }

    @Test
    void mlsHpkeVariesOnlyInItsConfigIndex() {
        int[] first = IdentityPaths.mlsHpke(ALICE, 0);
        int[] second = IdentityPaths.mlsHpke(ALICE, 1);

        assertEquals(1242, first[1] & ~H);
        assertEquals(65537, first[3] & ~H, "ed25519 with ROLE_HPKE");
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
            assertTrue(vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path).isOk(),
                    "vault rejected a path this class produced");
        }
    }
}
