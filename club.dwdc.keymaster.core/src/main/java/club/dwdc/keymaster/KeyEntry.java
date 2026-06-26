package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.Map;

/**
 * A key entry in the metadata store: a 5-level BIP-44 derivation path
 * paired with arbitrary string metadata.
 */
public record KeyEntry(HDPath path, Map<String, String> metadata) {

    /** Coin type (level 2), hardened bit stripped. */
    public int coinType()  { return path.get(1).num(); }

    /** Identity hash (level 3), hardened bit stripped. */
    public int identity()  { return path.get(2).num(); }

    /** Algorithm field (upper 15 bits of level 4). */
    public int algorithm() { return (path.get(3).num() >> 16) & 0x7FFF; }

    /** Variant field (middle 8 bits of level 4). */
    public int variant()   { return (path.get(3).num() >> 8) & 0xFF; }

    /** Role field (lower 8 bits of level 4). */
    public int role()      { return path.get(3).num() & 0xFF; }

    /**
     * Convert the derivation path to a raw int array suitable for {@link club.dwdc.keyvault.core.KeyVault#execute}.
     * Each int includes the hardened bit (0x80000000) when set.
     */
    public int[] toVaultPath() {
        int[] result = new int[path.size()];
        for (int idx = 0; idx < path.size(); idx++) {
            result[idx] = path.get(idx).i();
        }
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KeyEntry other)) return false;
        return path.equals(other.path);
    }

    @Override
    public int hashCode() {
        return path.hashCode();
    }
}
