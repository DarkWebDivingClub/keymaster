package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.VaultResult;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * A {@link PGPContentSignerBuilder} that delegates Ed25519 signing to a
 * {@link KeyVault} via {@link KeyVault#FN_SIGN}.
 *
 * <p>BouncyCastle's PGP EdDSA path pre-hashes the data with SHA-256 before
 * passing the 32-byte digest to Ed25519. This builder replicates that flow:
 * data is buffered, SHA-256 hashed, and the hash is sent to the vault for
 * signing. The {@code privateKey} parameter in {@link #build} is ignored;
 * only its key ID is used.
 */
class VaultPGPContentSignerBuilder implements PGPContentSignerBuilder {

    private final KeyVault vault;
    private final int[] vaultPath;

    VaultPGPContentSignerBuilder(KeyVault vault, int[] vaultPath) {
        this.vault = vault;
        this.vaultPath = vaultPath;
    }

    @Override
    public PGPContentSigner build(int signatureType, PGPPrivateKey privateKey) throws PGPException {
        long keyID = privateKey.getKeyID();

        return new PGPContentSigner() {
            private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            private byte[] cachedDigest;

            @Override
            public OutputStream getOutputStream() {
                return buffer;
            }

            @Override
            public byte[] getSignature() {
                VaultResult result = vault.execute(KeyVault.FN_SIGN, digest(), vaultPath);
                if (!result.isOk()) {
                    throw new IllegalStateException(
                            "vault signing failed: status=" + result.status());
                }
                return result.data();
            }

            @Override
            public byte[] getDigest() {
                return digest();
            }

            @Override
            public int getType() {
                return signatureType;
            }

            @Override
            public int getHashAlgorithm() {
                return HashAlgorithmTags.SHA256;
            }

            @Override
            public int getKeyAlgorithm() {
                return PublicKeyAlgorithmTags.EDDSA;
            }

            @Override
            public long getKeyID() {
                return keyID;
            }

            private byte[] digest() {
                if (cachedDigest == null) {
                    try {
                        cachedDigest = MessageDigest.getInstance("SHA-256")
                                .digest(buffer.toByteArray());
                    } catch (NoSuchAlgorithmException e) {
                        throw new IllegalStateException("SHA-256 not available", e);
                    }
                }
                return cachedDigest;
            }
        };
    }
}
