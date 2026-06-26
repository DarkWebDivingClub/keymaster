package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.VaultResult;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Service handler for GPG operations.
 *
 * <p>Provides {@code request_identities}, {@code sign_request}, and
 * {@code get_public_cert} methods backed by a {@link KeyVault} and a
 * list of {@link KeyEntry} objects.
 *
 * <p>Each KeyEntry represents one GPG role key (e.g. certification or signing).
 * The entry's metadata must include {@code "label"} and {@code "key_type"}.
 */
public class GpgServiceHandler extends AbstractServiceHandler {

    private final String publicCertArmor;

    /**
     * @param vault            vault for key derivation and signing
     * @param keys             GPG key entries (one per role)
     * @param publicCertArmor  pre-generated ASCII-armored OpenPGP public certificate
     */
    public GpgServiceHandler(KeyVault vault, List<KeyEntry> keys, String publicCertArmor) {
        super(vault, keys);
        this.publicCertArmor = publicCertArmor;
    }

    /**
     * Return the list of GPG identities (public keys + labels).
     */
    @ServiceMethod(value = "request_identities", defaultPolicy = ApprovalPolicy.APPROVE)
    public List<GpgIdentity> requestIdentities() {
        checkApproval("request_identities", "GPG identity listing");
        List<GpgIdentity> identities = new ArrayList<>();
        for (KeyEntry key : keys) {
            VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, key.toVaultPath());
            if (!pubResult.isOk()) {
                continue;
            }
            String keyType = key.metadata() != null
                    ? key.metadata().getOrDefault("key_type", "ed25519")
                    : "ed25519";
            String label = key.metadata() != null
                    ? key.metadata().getOrDefault("label", "")
                    : "";
            identities.add(new GpgIdentity(keyType, pubResult.data(), label));
        }
        return identities;
    }

    /**
     * Sign data with the key matching the request's public key.
     *
     * @throws IllegalArgumentException if no key matches the requested public key
     */
    @ServiceMethod(value = "sign_request", defaultPolicy = ApprovalPolicy.ASK)
    public GpgSignResponse signRequest(GpgSignRequest request) {
        checkApproval("sign_request", "GPG signing request");
        for (KeyEntry key : keys) {
            VaultResult pubResult = vault.execute(KeyVault.FN_GET_PUBLIC_KEY, null, key.toVaultPath());
            if (!pubResult.isOk()) {
                continue;
            }
            if (Arrays.equals(pubResult.data(), request.publicKey())) {
                VaultResult signResult = vault.execute(KeyVault.FN_SIGN, request.data(), key.toVaultPath());
                if (!signResult.isOk()) {
                    throw new IllegalStateException("sign failed: status=" + signResult.status());
                }
                return new GpgSignResponse(signResult.data());
            }
        }
        throw new IllegalArgumentException("key-mismatch");
    }

    /**
     * Return the pre-generated OpenPGP public certificate.
     *
     * @throws IllegalStateException if no public cert is available
     */
    @ServiceMethod(value = "get_public_cert", defaultPolicy = ApprovalPolicy.APPROVE)
    public GpgPublicCert getPublicCert() {
        checkApproval("get_public_cert", "GPG public certificate export");
        if (publicCertArmor == null) {
            throw new IllegalStateException("no GPG cert available");
        }
        return new GpgPublicCert(publicCertArmor);
    }
}
