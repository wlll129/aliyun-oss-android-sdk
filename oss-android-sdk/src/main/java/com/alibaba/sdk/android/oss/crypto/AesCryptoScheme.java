package com.alibaba.sdk.android.oss.crypto;

public class AesCryptoScheme extends CryptoScheme {
    @Override public String getKeyGeneratorAlgorithm() {return "AES";}
    @Override public int getKeyLengthInBits() {return 256;}
    @Override public String getContentChiperAlgorithm() {return "AES/CTR/NoPadding";}
    @Override public int getContentChiperIVLength() {return 16;}

    // 计算iv偏移
    @Override
    public byte[] adjustIV(byte[] iv, long dataStartPos) {
        if (iv.length != 16)
            throw new UnsupportedOperationException();

        final int blockSize = BLOCK_SIZE;
        long remainder = dataStartPos % blockSize;
        if (remainder != 0) {
            throw new IllegalArgumentException(
                    "Expected data start pos should be multiple of 16," + "but it was: " + dataStartPos);
        }

        long blockOffset = dataStartPos / blockSize;
        byte[] J0 = computeJ0(iv);
        return incrementBlocks(J0, blockOffset);
    }

    // 复制
    private byte[] computeJ0(byte[] nonce) {
        final int blockSize = BLOCK_SIZE;
        byte[] J0 = new byte[blockSize];
        System.arraycopy(nonce, 0, J0, 0, nonce.length);
        return J0;
    }
}
