package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;
import nostr.util.NostrUtil;

import java.util.Arrays;

/**
 * Vault-backed transport signer over exactly one key path.
 *
 * <p>Holds the path it may use and exposes only the capability — pubkey,
 * Schnorr signing, and ECDH. No private key enters this class; every operation
 * is delegated to the vault at the stored path.
 *
 * <p>One instance per connector. The transport caches the pubkey at
 * construction, so its signer must not change under it.
 */
final class VaultTransportSigner implements TransportSigner {

    private final KeyVault vault;
    private final int[] path;

    VaultTransportSigner(KeyVault vault, int[] path) {
        if (vault == null || path == null || path.length == 0) {
            throw new IllegalArgumentException("signer needs a vault and a path");
        }
        this.vault = vault;
        this.path = path.clone();
    }

    @Override
    public String getPubkey() {
        byte[] compressed = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, path).data();
        return NostrUtil.bytesToHex(Arrays.copyOfRange(compressed, 1, 33));
    }

    @Override
    public byte[] sign(byte[] hash) {
        return vault.execute(KeyVault.FN_SIGN, hash, path).data();
    }

    @Override
    public byte[] ecdh(byte[] peerPubKey) {
        return vault.execute(KeyVault.FN_KEY_AGREEMENT, peerPubKey, path).data();
    }
}
