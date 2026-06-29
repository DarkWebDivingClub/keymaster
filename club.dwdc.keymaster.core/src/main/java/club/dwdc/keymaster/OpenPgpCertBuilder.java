package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.VaultResult;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

import static org.bouncycastle.openpgp.PGPSignature.POSITIVE_CERTIFICATION;

/**
 * Builds an OpenPGP v4 public certificate (certification + signing key)
 * using only the vault's public API ({@link KeyVault#FN_GET_PUBLIC_KEY}
 * and {@link KeyVault#FN_SIGN}).
 *
 * <p>Private key material never leaves the vault. Placeholder private keys
 * are used to satisfy BouncyCastle's API; they are encrypted into a secret
 * key ring that is immediately discarded via {@code toCertificate()}.
 */
public final class OpenPgpCertBuilder {

    private OpenPgpCertBuilder() {
    }

    /**
     * Build an ASCII-armored OpenPGP public certificate containing a
     * certification primary key and a signing subkey.
     *
     * @param vault        vault for public-key retrieval and signing
     * @param certKey      key entry for the certification role (role 0)
     * @param signKey      key entry for the signing role (role 1)
     * @param pgpName      user name for the PGP User ID
     * @param pgpEmail     email for the PGP User ID
     * @param creationTime key creation timestamp
     * @return ASCII-armored public certificate
     */
    public static String buildPublicCert(
            KeyVault vault,
            KeyEntry certKey, KeyEntry signKey,
            String pgpName, String pgpEmail,
            Instant creationTime) throws PGPException, IOException {

        Date creation = Date.from(creationTime);

        // 1. Retrieve public keys from vault
        byte[] certPubBytes = getPublicKey(vault, certKey);
        byte[] signPubBytes = getPublicKey(vault, signKey);

        // 2. Create BcPGPKeyPairs with placeholder private keys
        BcPGPKeyPair certPair = ed25519PgpPair(certPubBytes, creation);
        BcPGPKeyPair signPair = ed25519PgpPair(signPubBytes, creation);

        // 3. Signer builders that delegate to the vault
        var certSigner = new VaultPGPContentSignerBuilder(vault, certKey.toVaultPath());
        var signSigner = new VaultPGPContentSignerBuilder(vault, signKey.toVaultPath());

        // 4. Primary key self-signature subpackets
        var primaryPackets = new PGPSignatureSubpacketGenerator();
        primaryPackets.setSignatureCreationTime(false, creation);
        primaryPackets.setKeyFlags(false, KeyFlags.CERTIFY_OTHER);
        primaryPackets.setPreferredHashAlgorithms(false, new int[]{
                HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA384, HashAlgorithmTags.SHA256
        });
        primaryPackets.setPreferredSymmetricAlgorithms(false, new int[]{
                SymmetricKeyAlgorithmTags.AES_256,
                SymmetricKeyAlgorithmTags.AES_192,
                SymmetricKeyAlgorithmTags.AES_128
        });
        primaryPackets.setPreferredCompressionAlgorithms(false, new int[]{
                CompressionAlgorithmTags.ZLIB,
                CompressionAlgorithmTags.ZIP,
                CompressionAlgorithmTags.UNCOMPRESSED
        });
        primaryPackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        var sha1 = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator generator = new PGPKeyRingGenerator(
                POSITIVE_CERTIFICATION,
                certPair,
                pgpName + " <" + pgpEmail + ">",
                sha1,
                primaryPackets.generate(),
                null,
                certSigner,
                null);

        // 5. Signing subkey binding signature with embedded back-signature
        var signingPackets = new PGPSignatureSubpacketGenerator();
        signingPackets.setSignatureCreationTime(false, creation);
        signingPackets.setKeyFlags(false, KeyFlags.SIGN_DATA);

        var backSigPackets = new PGPSignatureSubpacketGenerator();
        backSigPackets.setSignatureCreationTime(false, creation);
        PGPSignatureGenerator backSigGen = new PGPSignatureGenerator(
                signSigner, signPair.getPublicKey());
        backSigGen.init(PGPSignature.PRIMARYKEY_BINDING, signPair.getPrivateKey());
        backSigGen.setHashedSubpackets(backSigPackets.generate());
        signingPackets.addEmbeddedSignature(false, backSigGen.generateCertification(
                certPair.getPublicKey(), signPair.getPublicKey()));

        generator.addSubKey(signPair, signingPackets.generate(), null);

        // 6. Generate secret ring and immediately extract public certificate
        PGPSecretKeyRing secretRing = generator.generateSecretKeyRing();
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (ArmoredOutputStream out = new ArmoredOutputStream(buf)) {
            secretRing.toCertificate().encode(out);
        }
        return buf.toString(StandardCharsets.US_ASCII);
    }

    private static byte[] getPublicKey(KeyVault vault, KeyEntry key) {
        VaultResult result = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, key.toVaultPath());
        if (!result.isOk()) {
            throw new IllegalStateException(
                    "Failed to get public key: status=" + result.status());
        }
        return result.data();
    }

    private static BcPGPKeyPair ed25519PgpPair(byte[] publicKeyBytes, Date creationTime)
            throws PGPException {
        return new BcPGPKeyPair(
                PublicKeyAlgorithmTags.EDDSA,
                new AsymmetricCipherKeyPair(
                        new Ed25519PublicKeyParameters(publicKeyBytes, 0),
                        new Ed25519PrivateKeyParameters(new byte[32], 0)),
                creationTime);
    }
}
