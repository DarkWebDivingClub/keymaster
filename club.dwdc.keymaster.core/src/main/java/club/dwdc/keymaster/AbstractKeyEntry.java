package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.Map;

/**
 * Base class for typed key entries. Provides the BIP-44 derivation path
 * and the human-readable identity string (e.g. "alice@atlanta.com").
 */
public abstract class AbstractKeyEntry {

    private final HDPath path;
    private final String identity;

    protected AbstractKeyEntry(HDPath path, String identity) {
        this.path = path;
        this.identity = identity;
    }

    /** BIP-44 5-level derivation path. */
    public HDPath path() { return path; }

    /** Human-readable identity string. */
    public String identity() { return identity; }

    /** Coin type (level 2), hardened bit stripped. */
    public int coinType() { return path.get(1).num(); }

    /** Role field (lower 8 bits of level 4). */
    public int role() { return path.get(3).num() & 0xFF; }

    /** Convert to a generic {@link KeyEntry} for use with service handlers. */
    public KeyEntry toKeyEntry() {
        return new KeyEntry(path, Map.of());
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AbstractKeyEntry other)) return false;
        return path.equals(other.path);
    }

    @Override
    public int hashCode() {
        return path.hashCode();
    }
}
