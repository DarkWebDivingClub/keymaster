package club.dwdc.keymaster;

import club.dwdc.keymaster.X509CertCheck.Verdict;
import club.dwdc.keyvault.core.Bip32KeyVault;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Fixtures come from {@code src/test/resources/x509/make-fixtures.sh}, issued
 * over Alice's real TLS client public key.
 */
class X509CertCheckTest {

    private static final Identity ALICE = new Identity("alice@atlanta.com");

    /** 37.1.1's pinned P-256 vector at m/44'/1240'/1955269225'/196866'/0'. */
    private static final String ALICE_TLS_CLIENT_POINT =
            "04b99b60d501f8c4410839779fbea199d87b83dd675ffba53223529adfd0f05ac8"
            + "3c199adda4b7b7aaad50afd3ed4b230361e6ce56ea78790707cb7d84a81a2a81";

    private static Bip32KeyVault vault;

    @BeforeAll
    static void setUp() {
        // BC first, as KeyMaster does at runtime: the check must still parse with SUN.
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
        vault = new Bip32KeyVault(RealmTest.TEST_MNEMONIC);
    }

    private static Verdict check(String fixture) throws IOException {
        try (InputStream in = X509CertCheckTest.class.getResourceAsStream("/x509/" + fixture)) {
            assertNotNull(in, "missing fixture " + fixture);
            return X509CertCheck.check(vault, ALICE, X509Role.TLS_CLIENT, in.readAllBytes());
        }
    }

    @Test
    void acceptsThisKeyWithClientAuth() throws IOException {
        // The fixtures were issued over this key; if the vault drifts they are stale.
        assertEquals(ALICE_TLS_CLIENT_POINT, HexFormat.of().formatHex(
                X509CertCheck.vaultPoint(vault, ALICE, X509Role.TLS_CLIENT)));

        assertEquals(Verdict.ACCEPTED, check("tls-client-ok.pem"));
    }

    @Test
    void rejectsDifferentKey() throws IOException {
        assertEquals(Verdict.KEY_MISMATCH, check("different-key.pem"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"client-and-email.pem", "server-auth.pem", "any-eku.pem"})
    void rejectsMismatchingEku(String fixture) throws IOException {
        assertEquals(Verdict.EKU_MISMATCH, check(fixture));
    }

    @Test
    void rejectsEmptyEku() {
        assertEquals(Verdict.MALFORMED, X509CertCheck.checkEku(List.of(), X509Role.TLS_CLIENT));
    }

    @Test
    void acceptsNoEku() throws IOException {
        assertEquals(Verdict.ACCEPTED, check("no-eku.pem"));
    }

    @Test
    void acceptsExpired() throws IOException {
        assertEquals(Verdict.ACCEPTED, check("expired.pem"));
    }

    @Test
    void acceptsUnknownCa() throws IOException {
        assertEquals(Verdict.ACCEPTED, check("unknown-ca.pem"));
    }

    @Test
    void nullEkuIsAcceptedForEveryRole() {
        for (X509Role role : X509Role.values()) {
            assertEquals(Verdict.ACCEPTED, X509CertCheck.checkEku(null, role), role.name());
        }
    }

    @Test
    void noBcpkixOnTheClasspath() {
        assertThrows(ClassNotFoundException.class,
                () -> Class.forName("org.bouncycastle.cert.X509CertificateHolder"));
    }
}
