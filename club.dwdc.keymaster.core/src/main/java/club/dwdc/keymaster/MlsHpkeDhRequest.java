package club.dwdc.keymaster;

public record MlsHpkeDhRequest(byte[] hpkePubkey, byte[] peerPublic) {
}
