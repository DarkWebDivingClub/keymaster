package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.Protocol;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;

/**
 * The identity key paths — one authority for the trees marked
 * <b>FROZEN</b> in {@code doc/key-derivation.md}.
 *
 * <p>Every method here implements one row of that document's table, and the
 * document is the authority: if the two disagree, the document is right and
 * this class is a bug. {@code IdentityPathsTest} asserts the document's own
 * worked example, so they fail together or not at all.
 *
 * <p>These paths carry real, deployed keys — a user's SSH key, their OpenPGP
 * certificate, the Nostr key they publish with. <b>They can never change.</b>
 * The versioned KM-internal tree lives in {@link RealmPaths} instead, which is
 * the distinction the document draws and the reason these are two classes.
 *
 * <p>Paths are returned as {@code int[]} because that is what
 * {@link club.dwdc.keyvault.core.KeyVault#execute} takes; {@link #hdPath(int[])}
 * converts for the metadata store, which keys on {@link HDPath}.
 */
public final class IdentityPaths {

    private static final int H = 0x80000000;

    private IdentityPaths() {
    }

    /** {@code m/44'/1237'/mangle(id)'/schnorr'/cfg'} — the Nostr identity key. */
    public static int[] nostr(Identity identity) {
        return path(Protocol.NOSTR, identity,
                new AlgField(AlgField.ALG_SCHNORR, 0, 0).toIndex());
    }

    /** {@code m/44'/1238'/mangle(id)'/ed25519'/cfg'} — the SSH key. */
    public static int[] ssh(Identity identity) {
        return path(Protocol.SSH, identity,
                new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex());
    }

    /**
     * {@code m/44'/1239'/mangle(id)'/ed25519+role'/cfg'} — an OpenPGP key.
     *
     * @param role 0 certification, 1 signing
     */
    public static int[] gpg(Identity identity, int role) {
        return path(Protocol.OPENPGP, identity,
                new AlgField(AlgField.ALG_ED25519, 0, role).toIndex());
    }

    /** {@code m/44'/1242'/mangle(id)'/ed25519+sign'/cfg'} — the MLS signing key. */
    public static int[] mlsSign(Identity identity) {
        return path(Protocol.MLS, identity,
                new AlgField(AlgField.ALG_ED25519, 0, AlgField.ROLE_SIGN).toIndex());
    }

    /**
     * {@code m/44'/1242'/mangle(id)'/ed25519+hpke'/cfg(index)'} — one MLS HPKE
     * key. The index is a runtime sequence ({@code mls_next_hpke_init_key}), so
     * these cannot be resolved from the metadata store in advance.
     */
    public static int[] mlsHpke(Identity identity, int index) {
        return new int[]{
                44 | H,
                Protocol.MLS.coinType() | H,
                identity.mangled() | H,
                new AlgField(AlgField.ALG_ED25519, 0, AlgField.ROLE_HPKE).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, index).toIndex() | H
        };
    }

    /**
     * The same paths keyed by a pre-computed mangled identity, for callers that
     * hold one rather than an {@link Identity} — a key entry's level-3
     * component, for instance.
     */
    public static int[] mlsSignFor(int mangledIdentity) {
        return new int[]{
                44 | H,
                Protocol.MLS.coinType() | H,
                mangledIdentity | H,
                new AlgField(AlgField.ALG_ED25519, 0, AlgField.ROLE_SIGN).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };
    }

    /** As {@link #mlsHpke}, for a pre-computed mangled identity. */
    public static int[] mlsHpkeFor(int mangledIdentity, int index) {
        return new int[]{
                44 | H,
                Protocol.MLS.coinType() | H,
                mangledIdentity | H,
                new AlgField(AlgField.ALG_ED25519, 0, AlgField.ROLE_HPKE).toIndex() | H,
                new ConfigField(ConfigField.CSPRNG_NONE, index).toIndex() | H
        };
    }

    /** Convert a vault path to the {@link HDPath} the metadata store keys on. */
    public static HDPath hdPath(int[] path) {
        ChildNumber[] levels = new ChildNumber[path.length];
        for (int i = 0; i < path.length; i++) {
            levels[i] = new ChildNumber(path[i] & ~H, (path[i] & H) != 0);
        }
        return HDPath.m(levels);
    }

    private static int[] path(Protocol protocol, Identity identity, int algIndex) {
        return new int[]{
                44 | H,
                protocol.coinType() | H,
                identity.mangled() | H,
                algIndex | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };
    }
}
