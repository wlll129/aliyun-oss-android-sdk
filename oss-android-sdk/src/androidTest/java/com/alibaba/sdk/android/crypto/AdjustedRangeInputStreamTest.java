package com.alibaba.sdk.android.crypto;

import com.alibaba.sdk.android.oss.common.utils.IOUtils;
import com.alibaba.sdk.android.oss.crypto.AdjustedRangeInputStream;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static org.junit.Assert.assertEquals;

public class AdjustedRangeInputStreamTest {

    @Test
    public void testReadBuffer() throws IOException {
        String content = "012345678901234567890123456789012345678901234567890123456789";
        int begin = 0;
        int end = 37;
        AdjustedRangeInputStream adjIs = new AdjustedRangeInputStream(new ByteArrayInputStream(content.getBytes()), begin, end);
        assertEquals(adjIs.available(), end - begin + 1);
        String str = IOUtils.readStreamAsString(adjIs, "UTF-8");
        assertEquals(content.substring(begin, end + 1), str);

        begin = 1;
        end = 37;
        adjIs = new AdjustedRangeInputStream(new ByteArrayInputStream(content.getBytes()), begin, end);
        str = IOUtils.readStreamAsString(adjIs, "UTF-8");
        assertEquals(content.substring(begin, end + 1), str);

        begin = 17;
        end = 37;
        InputStream in = new ByteArrayInputStream(content.getBytes());
        // Simulate it as a decipher stream.
        in.skip(16);
        adjIs = new AdjustedRangeInputStream(in, begin, end);
        str = IOUtils.readStreamAsString(adjIs, "UTF-8");
        assertEquals(content.substring(begin, end + 1), str);
    }


    @Test
    public void testReadOneByte() throws IOException {
        String content = "012345678901234567890123456789012345678901234567890123456789";
        int begin = 1;
        int end = 37;
        AdjustedRangeInputStream in = new AdjustedRangeInputStream(new ByteArrayInputStream(content.getBytes()), begin, end);
        int ret = in.read();
        assertEquals(ret, content.charAt(begin));
    }
}
