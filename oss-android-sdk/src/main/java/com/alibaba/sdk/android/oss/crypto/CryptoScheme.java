package com.alibaba.sdk.android.oss.crypto;

import java.nio.ByteBuffer;

public abstract class CryptoScheme {

    public static final int BLOCK_SIZE = 16;

    public abstract String getKeyGeneratorAlgorithm();

    public abstract int getKeyLengthInBits();

    public abstract String getContentChiperAlgorithm();

    public abstract int getContentChiperIVLength();

    public abstract byte[] adjustIV(byte[] iv, long dataStartPos);

    final static CryptoScheme getCryptoScheme(ContentCryptoMode contentCryptoMode) {
        switch (contentCryptoMode) {
            case AES_CTR_MODE:
            default:
                return new AesCryptoScheme();
        }
    }
    /**
     * Increment the rightmost 64 bits of a 16-byte counter by the specified delta.
     * Both the specified delta and the resultant value must stay within the
     * capacity of 64 bits. (Package private for testing purposes.)
     *
     * @param counter
     *            a 16-byte counter.
     * @param blockDelta
     *            the number of blocks (16-byte) to increment
     */
    public static byte[] incrementBlocks(byte[] counter, long blockDelta) {
        if (blockDelta == 0)
            return counter;
        if (counter == null || counter.length != 16)
            throw new IllegalArgumentException();

        ByteBuffer bb = ByteBuffer.allocate(8);
        for (int i = 12; i <= 15; i++)
            bb.put(i - 8, counter[i]);
        long val = bb.getLong() + blockDelta; // increment by delta
        bb.rewind();
        byte[] result = bb.putLong(val).array();

        for (int i = 8; i <= 15; i++)
            counter[i] = result[i - 8];
        return counter;
    }

    public static CryptoScheme fromCEKAlgo(String cekAlgo) {
        if ("AES/CTR/NoPadding".equals(cekAlgo)) {
            return new AesCryptoScheme();
        }
        throw new UnsupportedOperationException("Unsupported content encryption scheme: " + cekAlgo);
    }
}
