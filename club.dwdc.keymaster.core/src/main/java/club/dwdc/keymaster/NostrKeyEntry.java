package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.Map;

/**
 * Nostr key metadata entry.
 */
public class NostrKeyEntry extends AbstractKeyEntry {

    private final String pubkey;

    public NostrKeyEntry(HDPath path, String identity, String pubkey) {
        super(path, identity);
        this.pubkey = pubkey;
    }

    public String pubkey() { return pubkey; }

    @Override
    public KeyEntry toKeyEntry() {
        return new KeyEntry(path(), Map.of("pubkey", pubkey));
    }
}
