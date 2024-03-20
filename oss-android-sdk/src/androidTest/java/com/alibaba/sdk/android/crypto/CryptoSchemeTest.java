package com.alibaba.sdk.android.crypto;

import com.alibaba.sdk.android.oss.crypto.CryptoScheme;

import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertTrue;

public class CryptoSchemeTest {
    @Test
    public void testIncrementBlocks() {
        byte[] iv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04};
        byte[] retIV = CryptoScheme.incrementBlocks(iv, 0X1122334400000000L);
        byte[] expectedIV = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x03, 0x04};
        assertTrue(Arrays.equals(retIV, expectedIV));
    }

    @Test
    public void testIncrementBlocksUnnormal() {
        byte[] iv = new byte[]{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05};
        CryptoScheme.incrementBlocks(iv, 0X1122334400000000L);

        iv = null;
        CryptoScheme.incrementBlocks(iv, 0X1122334400000000L);
    }
}
