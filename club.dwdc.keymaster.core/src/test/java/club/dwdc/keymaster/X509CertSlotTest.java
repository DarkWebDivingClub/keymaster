package club.dwdc.keymaster;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class X509CertSlotTest {

    @Test
    void roundTripsThroughInMemoryStore() {
        var store = new InMemoryKeyMetaDataStore();
        var path = IdentityPaths.hdPath(
                IdentityPaths.x509(new Identity("alice@atlanta.com"), X509Role.TLS_CLIENT));
        byte[] der = {0x30, (byte) 0x82, 0x01, 0x00, 0x7F, (byte) 0xFF};

        var entry = new KeyEntry(path, Map.of("identity", "alice@atlanta.com"));
        store.addKey(X509CertSlot.with(entry, der));

        KeyEntry got = store.getKey(path);
        assertArrayEquals(der, X509CertSlot.get(got).orElseThrow());
        assertEquals("alice@atlanta.com", got.metadata().get("identity"), "other metadata kept");
        assertTrue(X509CertSlot.get(entry).isEmpty(), "absent slot reads as empty");
    }
}
