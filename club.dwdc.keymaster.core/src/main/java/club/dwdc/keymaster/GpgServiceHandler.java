package club.dwdc.keymaster;

import club.dwdc.keyvault.core.KeyVault;
import club.dwdc.keyvault.core.VaultResult;

import java.time.Instant;
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

    /**
     * @param vault vault for key derivation and signing
     * @param keys  GPG key entries (one per role); metadata must include
     *              {@code identity}, {@code creation_time}, {@code pgp_name},
     *              {@code pgp_email}, {@code label}, and {@code key_type}
     */
    public GpgServiceHandler(KeyVault vault, List<KeyEntry> keys) {
        super(vault, keys);
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
     * Generate and return the OpenPGP public certificate on-the-fly from key entry metadata.
     *
     * @throws IllegalStateException if generation fails or metadata is missing
     */
    @ServiceMethod(value = "get_public_cert", defaultPolicy = ApprovalPolicy.APPROVE)
    public GpgPublicCert getPublicCert() {
        checkApproval("get_public_cert", "GPG public certificate export");
        if (keys.isEmpty()) {
            throw new IllegalStateException("no GPG keys available");
        }
        try {
            StringBuilder allCerts = new StringBuilder();
            for (int i = 0; i + 1 < keys.size(); i += 2) {
                KeyEntry certKey = keys.get(i);
                KeyEntry signKey = keys.get(i + 1);
                String pgpName = certKey.metadata().get("pgp_name");
                String pgpEmail = certKey.metadata().get("pgp_email");
                long epochSec = Long.parseLong(certKey.metadata().get("creation_time"));
                Instant creationTime = Instant.ofEpochSecond(epochSec);
                allCerts.append(OpenPgpCertBuilder.buildPublicCert(
                        vault, certKey, signKey, pgpName, pgpEmail, creationTime));
            }
            return new GpgPublicCert(allCerts.toString());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate GPG cert", e);
        }
    }
}
