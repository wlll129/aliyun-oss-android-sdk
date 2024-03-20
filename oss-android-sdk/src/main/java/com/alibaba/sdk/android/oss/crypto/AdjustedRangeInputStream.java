package com.alibaba.sdk.android.oss.crypto;

import java.io.IOException;
import java.io.InputStream;

import static com.alibaba.sdk.android.oss.crypto.SdkRuntime.shouldAbort;

public class AdjustedRangeInputStream extends InputStream {
    private InputStream decryptedContents;
    private long virtualAvailable;
    private boolean closed;

    /**
     * Creates a new DecryptedContentsInputStream object.
     *
     * @param objectContents
     *      The input stream containing the object contents retrieved from OSS
     * @param rangeBeginning
     *      The position of the left-most byte desired by the user
     * @param rangeEnd
     *      The position of the right-most byte desired by the user
     * @throws IOException
     *      If there are errors skipping to the left-most byte desired by the user.
     */
    public AdjustedRangeInputStream(InputStream objectContents, long rangeBeginning, long rangeEnd) throws IOException {
        this.decryptedContents = objectContents;
        this.closed = false;
        initializeForRead(rangeBeginning, rangeEnd);
    }

    /**
     * Aborts the inputstream operation if thread is interrupted.
     * interrupted status of the thread is cleared by this method.
     *
     * @throws RuntimeException with ClientErrorCode INPUTSTREAM_READING_ABORTED if thread aborted.
     */
    protected final void abortIfNeeded() {
        if (shouldAbort()) {
            abort();
            throw new RuntimeException("Thread aborted, inputStream aborted...");
        }
    }

    private void abort() {
    }

    /**
     * Skip to the start location of the range of bytes desired by the user.
     */
    private void initializeForRead(long rangeBeginning, long rangeEnd) throws IOException {
        int numBytesToSkip;
        if (rangeBeginning < CryptoScheme.BLOCK_SIZE) {
            numBytesToSkip = (int) rangeBeginning;
        } else {
            int offsetIntoBlock = (int) (rangeBeginning % CryptoScheme.BLOCK_SIZE);
            numBytesToSkip = offsetIntoBlock;
        }
        if (numBytesToSkip != 0) {
            while (numBytesToSkip > 0) {
                this.decryptedContents.read();
                numBytesToSkip--;
            }
        }
        this.virtualAvailable = (rangeEnd - rangeBeginning) + 1;
    }

    @Override
    public int read() throws IOException {
        abortIfNeeded();
        int result;

        if (this.virtualAvailable <= 0) {
            result = -1;
        } else {
            result = this.decryptedContents.read();
        }

        if (result != -1) {
            this.virtualAvailable--;
        } else {
            this.virtualAvailable = 0;
            close();
        }

        return result;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        abortIfNeeded();
        int numBytesRead;
        if (this.virtualAvailable <= 0) {
            numBytesRead = -1;
        } else {
            if (length > this.virtualAvailable) {
                length = (this.virtualAvailable < Integer.MAX_VALUE) ? (int) this.virtualAvailable : Integer.MAX_VALUE;
            }
            numBytesRead = this.decryptedContents.read(buffer, offset, length);
        }

        if (numBytesRead != -1) {
            this.virtualAvailable -= numBytesRead;
        } else {
            this.virtualAvailable = 0;
            close();
        }
        return numBytesRead;
    }

    @Override
    public int available() throws IOException {
        abortIfNeeded();
        int available = this.decryptedContents.available();
        if (available < this.virtualAvailable) {
            return available;
        } else {
            return (int) this.virtualAvailable;
        }
    }

    @Override
    public void close() throws IOException {
        if (!this.closed) {
            this.closed = true;
            if (this.virtualAvailable == 0) {
                drainInputStream(decryptedContents);
            }
            this.decryptedContents.close();
        }
        abortIfNeeded();
    }

    private static void drainInputStream(InputStream in) {
        try {
            while (in.read() != -1) {
            }
        } catch (IOException ignored) {
        }
    }

    public InputStream getWrappedInputStream() {
        return decryptedContents;
    }
}
