package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Alg;
import club.dwdc.keyvault.core.Bip32KeyVault;
import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.VaultResult;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Mission 48.3, step 6: the secp256k1 keys must be the same in keymaster 0.9.0
 * (keyvault 0.6.0) as in 0.8.1 (keyvault 0.5.0). Nostr npubs, the realm
 * connector xpub sent to an avatar as {@code realm_xpub}, the service channel
 * keys derived below it, NIP-44 ECDH and Schnorr signatures.
 *
 * <p>The expected values were produced by keymaster 0.8.1 and keyvault 0.5.0
 * themselves (the released jars, 2026-11-19), not by this code.
 */
class UnchangedKeysGoldenTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String LOGIN_XPUB =
            "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz";

    private final KeyVault vault = new Bip32KeyVault(RealmTest.TEST_MNEMONIC);
    private final int[] alice = IdentityPaths.nostr(new Identity("alice@atlanta.com"));
    private final int[] bob = IdentityPaths.nostr(new Identity("bob@biloxi.com"));

    private byte[] ok(VaultResult r) {
        assertTrue(r.isOk(), "status " + r.status());
        return r.data();
    }

    private byte[] pub(int[] path) {
        return ok(vault.execute(Alg.SECP256K1, KeyVault.FN_GET_PUBLIC_KEY, 0, null, path));
    }

    @Test
    void nostrKey() {
        assertEquals("03fa7851825be694a747ec9d93ea0b46be6f36a40af6ec3c5b2682d1dafe59dd12", HEX.formatHex(pub(alice)));
    }

    @Test
    void nip44Ecdh() {
        assertEquals("019578d1c12e0cc60bd3ddb0f1e7ce0562101885908c8085d1c6f71d38c70f17",
                HEX.formatHex(ok(vault.execute(Alg.SECP256K1, KeyVault.FN_KEY_AGREEMENT, 0, pub(bob), alice))));
    }

    @Test
    void schnorrSignature() {
        byte[] hash = new byte[32];
        for (int i = 0; i < 32; i++) {
            hash[i] = (byte) i;
        }
        assertEquals("287eb6a99ccccd05cdb175fe95f18de20e684dfcd33752515398f3734cb08923"
                        + "bdd1b67efdad443ab2288ecf984f66316422f1ae3adbf68f1f8c30eeaddfced4",
                HEX.formatHex(ok(vault.execute(Alg.SECP256K1, KeyVault.FN_SIGN,
                        KeyVault.OPT_SECP256K1_SCHNORR, hash, alice))));
    }

    @Test
    void realmXpubAndServiceChannels() {
        int[] connector = RealmPaths.connector(7, LOGIN_XPUB);
        VaultResult c = vault.execute(Alg.SECP256K1, KeyVault.FN_GET_PUBLIC_KEY, 0, null, connector);
        assertTrue(c.isOk());
        assertEquals("xpub661MyMwAqRbcGuJ9eAsE2X786RKwgVpp9rhaCFaGUmrEqkE88i3ggV6HiMYs6veJpfd8YT7XkZP5No4Bb4dLpFrxxXkvWehhSiXWBNUcqHb",
                HDKeyDerivation.createMasterPubKeyFromBytes(c.data(), c.chainCode()).serializePubB58(BitcoinNetwork.MAINNET));
        assertEquals("02fa295c84c4d2ecb8d27d28aabcb044ac07652a36bd93d37fdd7720522b57fa43",
                HEX.formatHex(pub(RealmPaths.serviceChannel(connector, "ssh", 0))));
        assertEquals("02d85e68ef7468b131cfda4ff205a35b37f6fbd7b2dd57b0bd238ec5d7f8b69b2e",
                HEX.formatHex(pub(RealmPaths.serviceChannel(connector, "gpg", 0))));
        assertEquals("028ee241282ba171336195d0bd697f6243a82cf96ca43b4b0df8aca3006c2764fa",
                HEX.formatHex(pub(RealmPaths.serviceChannel(connector, "nostr", 0))));
    }
}
