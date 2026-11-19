package club.dwdc.keymaster;

import club.dwdc.keyvault.core.Alg;
import club.dwdc.keyvault.core.ConfigField;
import club.dwdc.keyvault.core.Protocol;
import club.dwdc.keyvault.core.UseField;
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
 *
 * <p>keymaster 0.9.0, keyvault 0.6.0 (mission 48.3): level 4 is {@code use'} =
 * {@code UseField(variant = option, role)}; the algorithm is no longer in the
 * path but passed to the vault as {@link Alg} ({@link #algFor}). Roles are per
 * protocol, below. SSH, OpenPGP, MLS and X.509 keys changed in 0.9.0 (SLIP-10);
 * Nostr paths and keys did not.
 */
public final class IdentityPaths {

    private static final int H = 0x80000000;

    // ── Roles, per protocol (path[3] bits 7-0). Frozen. ─────────────────

    /** Nostr: the identity key (signing and NIP-44 ECDH share it). */
    public static final int NOSTR_ROLE = 0;
    /** SSH: user authentication. */
    public static final int SSH_ROLE = 0;
    /** OpenPGP: primary key, certification. */
    public static final int OPENPGP_CERTIFICATION = 0;
    /** OpenPGP: signing subkey. */
    public static final int OPENPGP_SIGNING = 1;
    /** OpenPGP: X25519 encryption subkey. Reserved, not yet created (48.3 answered question 2). */
    public static final int OPENPGP_ENCRYPTION = 2;
    /** MLS: signature key. */
    public static final int MLS_SIGN = 0;
    /** MLS: HPKE (init) keys, indexed by {@code cfg}. */
    public static final int MLS_HPKE = 1;

    private IdentityPaths() {
    }

    /**
     * The vault algorithm a protocol's keys use by default: Nostr and the realm
     * tree secp256k1, SSH, OpenPGP and MLS Ed25519, X.509 P-256. A key entry
     * may record another in its metadata ({@code alg}); SSH and MLS are allowed
     * P-256 by the vault's binding check.
     */
    public static Alg algFor(int coinType) {
        if (coinType == Protocol.SSH.coinType()
                || coinType == Protocol.OPENPGP.coinType()
                || coinType == Protocol.MLS.coinType()
                || coinType == Protocol.WIREGUARD.coinType()) {
            return Alg.ED25519;
        }
        if (coinType == Protocol.X509.coinType()) {
            return Alg.P256;
        }
        return Alg.SECP256K1;
    }

    /** {@code m/44'/1237'/mangle(id)'/0'/cfg'} — the Nostr identity key. Unchanged in 0.9.0. */
    public static int[] nostr(Identity identity) {
        return path(Protocol.NOSTR, identity, use(NOSTR_ROLE));
    }

    /** {@code m/44'/1238'/mangle(id)'/0'/cfg'} — the SSH key (was {@code 65536'} before 0.9.0). */
    public static int[] ssh(Identity identity) {
        return path(Protocol.SSH, identity, use(SSH_ROLE));
    }

    /**
     * {@code m/44'/1239'/mangle(id)'/role'/cfg'} — an OpenPGP key (was
     * {@code 65536'}/{@code 65537'} before 0.9.0).
     *
     * @param role {@link #OPENPGP_CERTIFICATION} or {@link #OPENPGP_SIGNING}
     */
    public static int[] gpg(Identity identity, int role) {
        return path(Protocol.OPENPGP, identity, use(role));
    }

    /** {@code m/44'/1242'/mangle(id)'/0'/cfg'} — the MLS signing key. */
    public static int[] mlsSign(Identity identity) {
        return path(Protocol.MLS, identity, use(MLS_SIGN));
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
                use(MLS_HPKE) | H,
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
                use(MLS_SIGN) | H,
                new ConfigField(ConfigField.CSPRNG_NONE, 0).toIndex() | H
        };
    }

    /** As {@link #mlsHpke}, for a pre-computed mangled identity. */
    public static int[] mlsHpkeFor(int mangledIdentity, int index) {
        return new int[]{
                44 | H,
                Protocol.MLS.coinType() | H,
                mangledIdentity | H,
                use(MLS_HPKE) | H,
                new ConfigField(ConfigField.CSPRNG_NONE, index).toIndex() | H
        };
    }

    /**
     * {@code m/44'/1240'/mangle(id)'/role'/cfg'} — an X.509 key (P-256). Alice's
     * TLS client key is {@code m/44'/1240'/1955269225'/2'/0'} (was
     * {@code 196866'} = {@code 0x30102} before 0.9.0).
     */
    public static int[] x509(Identity identity, X509Role role) {
        return path(Protocol.X509, identity, use(role.number()));
    }

    /**
     * The label of an X.509 key: {@code "<identity> <role-token>"}, e.g.
     * {@code "alice@atlanta.com tls-client"}. Generated, never stored; it is
     * the PKCS#11 {@code CKA_LABEL} of the key's objects.
     */
    public static String x509Label(Identity identity, X509Role role) {
        return identity.name() + " " + role.token();
    }

    /** Convert a vault path to the {@link HDPath} the metadata store keys on. */
    public static HDPath hdPath(int[] path) {
        ChildNumber[] levels = new ChildNumber[path.length];
        for (int i = 0; i < path.length; i++) {
            levels[i] = new ChildNumber(path[i] & ~H, (path[i] & H) != 0);
        }
        return HDPath.m(levels);
    }

    /**
     * A vault path as the string {@code key-metadata.json} stores it, e.g.
     * {@code m/44'/1240'/1955269225'/2'/0'}: {@code "m"}, then
     * {@code /index} with {@code '} when hardened. Must stay identical to the
     * desktop store's {@code HDPathTypeAdapter}; {@code FileKeyMetaDataStoreTest}
     * pins the two together. The X.509 service matches request paths against
     * this string exactly — no parsing.
     */
    public static String pathString(int[] path) {
        StringBuilder sb = new StringBuilder("m");
        for (int level : path) {
            sb.append('/').append(level & ~H);
            if ((level & H) != 0) {
                sb.append('\'');
            }
        }
        return sb.toString();
    }

    /** Level 4 for the default scheme (option 0) and a role. */
    private static int use(int role) {
        return new UseField(0, role).toIndex();
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
