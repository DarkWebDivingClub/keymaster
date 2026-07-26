package club.dwdc.keymaster;

import org.bitcoinj.crypto.HDPath;

import java.util.Map;

/**
 * SSH key metadata entry.
 */
public class SSHKeyEntry extends AbstractKeyEntry {

    private final String comment;

    public SSHKeyEntry(HDPath path, String identity, String comment) {
        super(path, identity);
        this.comment = comment;
    }

    public String comment() { return comment; }

    @Override
    public KeyEntry toKeyEntry() {
        return new KeyEntry(path(), Map.of("comment", comment));
    }
}
