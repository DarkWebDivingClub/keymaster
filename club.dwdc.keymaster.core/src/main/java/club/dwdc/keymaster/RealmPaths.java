package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;

/**
 * The KM-internal key paths — one authority for the tree marked
 * <b>VERSIONED</b> in {@code doc/key-derivation.md}.
 *
 * <p>This tree carries no user identity. It exists so a realm and each of its
 * avatar connections get cryptographically distinct channel keys, and because
 * it is versioned it <i>can</i> change — which is exactly why it is separate
 * from {@link IdentityPaths}, whose trees cannot.
 *
 * <p>The handshake is not here: attach and detach are signed with the realm's
 * primary identity Nostr key, out of the frozen tree.
 */
public final class RealmPaths {

    private static final int H = 0x80000000;

    /** BIP-43 purpose for this tree: {@code mangle("keymaster")} = 0x53C20D30. */
    public static final int KM_PURPOSE = Bip32KeyDerivator.mangle("keymaster");

    /** Scheme version of the layout below. */
    public static final int KM_SCHEME = 1;

    private RealmPaths() {
    }

    /**
     * {@code m/mangle("keymaster")'/scheme'/realmId'/alg'/mangle(login_xpub)'} —
     * one avatar link's connection key, exported to that avatar as
     * {@code realm_xpub} and the parent of its service channel keys.
     *
     * <p>All five levels are hardened. The algorithm level is required rather
     * than decorative: the vault rejects paths shorter than five levels and
     * reads the key type from level 4. These are Schnorr keys — Schnorr
     * signatures for channel events, secp256k1 ECDH for NIP-44.
     */
    public static int[] connector(int realmId, String avatarLoginXpub) {
        return new int[]{
                KM_PURPOSE | H,
                KM_SCHEME | H,
                realmId | H,
                new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex() | H,
                Bip32KeyDerivator.mangle(avatarLoginXpub) | H
        };
    }

    /**
     * {@code <connector path>/mangle(service_type)/seq} — one service channel.
     *
     * <p>Non-hardened, and necessarily so: the avatar derives the same two
     * levels from the exported xpub, holding a public key and no private one.
     */
    public static int[] serviceChannel(int[] connectorPath, String serviceType, int seq) {
        int[] path = new int[connectorPath.length + 2];
        System.arraycopy(connectorPath, 0, path, 0, connectorPath.length);
        path[connectorPath.length] = Bip32KeyDerivator.mangle(serviceType);
        path[connectorPath.length + 1] = seq;
        return path;
    }
}
