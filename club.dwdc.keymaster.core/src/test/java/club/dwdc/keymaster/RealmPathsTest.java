package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.Protocol;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** The versioned KM-internal tree, as stated in {@code doc/key-derivation.md}. */
class RealmPathsTest {

    private static final int H = 0x80000000;
    private static final String LOGIN_XPUB =
            "xpub6CUGRUonZSQ4TWtTMmzXdrXDtyPWKiKbbqnWxx2qaGvxZ2x";

    @Test
    void purposeIsMangleOfKeymaster() {
        assertEquals(1405226288, RealmPaths.KM_PURPOSE);
        assertEquals(0x53C20D30, RealmPaths.KM_PURPOSE);
        assertEquals(1, RealmPaths.KM_SCHEME);
    }

    @Test
    void connectorIsFiveHardenedLevels() {
        int[] path = RealmPaths.connector(1234, LOGIN_XPUB);

        assertEquals(5, path.length, "purpose / scheme / realm / alg / connector");
        for (int level : path) {
            assertTrue((level & H) != 0, "every KM-side level is hardened");
        }
        assertEquals(1405226288, path[0] & ~H);
        assertEquals(1, path[1] & ~H);
        assertEquals(1234, path[2] & ~H);
        assertEquals(0, path[3] & ~H, "AlgField(SCHNORR,0,0) — the vault reads level 4");
        assertEquals(Bip32KeyDerivator.mangle(LOGIN_XPUB), path[4] & ~H);
    }

    @Test
    void connectorIsNotInAnIdentityNamespace() {
        int[] path = RealmPaths.connector(1234, LOGIN_XPUB);
        assertNotEquals(44, path[0] & ~H, "no BIP-44 purpose");
        assertNotEquals(Protocol.NOSTR.coinType(), path[1] & ~H, "no nostr coin type");
    }

    @Test
    void theVaultAcceptsAConnectorPath() {
        var vault = new Bip32KeyVault(RealmTest.TEST_MNEMONIC);
        var result = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null,
                RealmPaths.connector(1234, LOGIN_XPUB));

        assertTrue(result.isOk(), "status=" + result.status());
        assertNotNull(result.chainCode(), "an xpub needs the chain code");
    }

    @Test
    void differentRealmsAndAvatarsGiveDifferentPaths() {
        int[] a = RealmPaths.connector(1234, LOGIN_XPUB);
        int[] b = RealmPaths.connector(5678, LOGIN_XPUB);
        int[] c = RealmPaths.connector(1234, LOGIN_XPUB + "x");

        assertNotEquals(a[2], b[2], "the realm discriminates");
        assertNotEquals(a[4], c[4], "the avatar discriminates");
    }

    @Test
    void serviceChannelAddsTwoNonHardenedLevels() {
        int[] connector = RealmPaths.connector(1234, LOGIN_XPUB);
        int[] channel = RealmPaths.serviceChannel(connector, "ssh", 0);

        assertEquals(7, channel.length);
        assertArrayEquals(connector, java.util.Arrays.copyOf(channel, 5));
        assertEquals(Bip32KeyDerivator.mangle("ssh"), channel[5]);
        assertEquals(0, channel[6]);
        assertEquals(0, channel[5] & H, "below the exported xpub, derivation must be non-hardened");
        assertEquals(0, channel[6] & H);
    }

    @Test
    void eachServiceGetsItsOwnChannel() {
        int[] connector = RealmPaths.connector(1234, LOGIN_XPUB);
        assertNotEquals(RealmPaths.serviceChannel(connector, "ssh", 0)[5],
                RealmPaths.serviceChannel(connector, "gpg", 0)[5]);
    }

    @Test
    void theVaultAcceptsAServiceChannelPath() {
        var vault = new Bip32KeyVault(RealmTest.TEST_MNEMONIC);
        int[] channel = RealmPaths.serviceChannel(
                RealmPaths.connector(1234, LOGIN_XPUB), "nostr", 0);

        assertTrue(vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, channel).isOk());
    }
}
