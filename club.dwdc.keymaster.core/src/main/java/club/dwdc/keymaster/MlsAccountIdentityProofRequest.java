package club.dwdc.keymaster;

public record MlsAccountIdentityProofRequest(byte[] accountIdentity, byte[] mlsSignaturePublicKey,
                                              int ciphersuite, int signatureScheme) {
}
