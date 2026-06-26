package club.dwdc.keymaster;

import club.dwdc.keyvault.core.AlgField;
import club.dwdc.keyvault.core.Bip32KeyDerivator;
import club.dwdc.keyvault.core.Protocol;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.HDPath;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class KeyEntryTest {

    static HDPath sshPath(String identity) {
        return HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.SSH.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle(identity), true),
            new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 0).toIndex(), true),
            new ChildNumber(0, true)
        );
    }

    @Test
    void coinTypeExtractsWithoutHardenedBit() {
        KeyEntry entry = new KeyEntry(sshPath("alice"), Map.of());
        assertEquals(Protocol.SSH.coinType(), entry.coinType());
    }

    @Test
    void identityExtractsWithoutHardenedBit() {
        KeyEntry entry = new KeyEntry(sshPath("alice"), Map.of());
        assertEquals(Bip32KeyDerivator.mangle("alice"), entry.identity());
    }

    @Test
    void algorithmExtractsUpper15Bits() {
        KeyEntry entry = new KeyEntry(sshPath("alice"), Map.of());
        assertEquals(AlgField.ALG_ED25519, entry.algorithm());
    }

    @Test
    void variantExractsMiddle8Bits() {
        HDPath path = HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.SSH.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle("alice"), true),
            new ChildNumber(new AlgField(AlgField.ALG_ED25519, 3, 0).toIndex(), true),
            new ChildNumber(0, true)
        );
        KeyEntry entry = new KeyEntry(path, Map.of());
        assertEquals(3, entry.variant());
    }

    @Test
    void roleExtractsLower8Bits() {
        HDPath path = HDPath.m(
            new ChildNumber(44, true),
            new ChildNumber(Protocol.SSH.coinType(), true),
            new ChildNumber(Bip32KeyDerivator.mangle("alice"), true),
            new ChildNumber(new AlgField(AlgField.ALG_ED25519, 0, 5).toIndex(), true),
            new ChildNumber(0, true)
        );
        KeyEntry entry = new KeyEntry(path, Map.of());
        assertEquals(5, entry.role());
    }

    @Test
    void equalityByPathContent() {
        HDPath path1 = sshPath("alice");
        HDPath path2 = sshPath("alice");
        assertEquals(new KeyEntry(path1, Map.of()), new KeyEntry(path2, Map.of("k", "v")));
    }

    @Test
    void inequalityByPath() {
        KeyEntry a = new KeyEntry(sshPath("alice"), Map.of());
        KeyEntry b = new KeyEntry(sshPath("bob"), Map.of());
        assertNotEquals(a, b);
    }

    @Test
    void emptyMetadata() {
        HDPath path = sshPath("alice");
        KeyEntry withNull = new KeyEntry(path, null);
        assertNull(withNull.metadata());

        KeyEntry withEmpty = new KeyEntry(path, Map.of());
        assertTrue(withEmpty.metadata().isEmpty());
    }
}
