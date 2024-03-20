package com.alibaba.sdk.android.oss.crypto;

import com.alibaba.sdk.android.oss.ClientException;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import static com.alibaba.sdk.android.oss.crypto.SdkRuntime.shouldAbort;

public class SdkFilterInputStream extends FilterInputStream {
    private volatile boolean aborted = false;

    public SdkFilterInputStream(InputStream in) {
        super(in);
    }

    /**
     * @return The wrapped stream.
     */
    public InputStream getDelegateStream() {
        return in;
    }

    /**
     * Aborts the inputstream operation if thread is interrupted.
     * interrupted status of the thread is cleared by this method.
     *
     * @throws ClientException with ClientErrorCode INPUTSTREAM_READING_ABORTED if thread aborted.
     */
    protected final void abortIfNeeded() {
        if (shouldAbort()) {
            abort();
            throw new RuntimeException("Thread aborted, inputStream aborted...");
        }
    }

    public void abort() {
        if (in instanceof SdkFilterInputStream) {
            ((SdkFilterInputStream) in).abort();
        }
        aborted = true;
    }

    public boolean isAborted() {
        return aborted;
    }

    @Override
    public int read() throws IOException {
        abortIfNeeded();
        return in.read();
    }

    @Override
    public int read(byte b[], int off, int len) throws IOException {
        abortIfNeeded();
        return in.read(b, off, len);
    }

    @Override
    public long skip(long n) throws IOException {
        abortIfNeeded();
        return in.skip(n);
    }

    @Override
    public int available() throws IOException {
        abortIfNeeded();
        return in.available();
    }

    @Override
    public void close() throws IOException {
        in.close();
        abortIfNeeded();
    }

    @Override
    public synchronized void mark(int readlimit) {
        abortIfNeeded();
        in.mark(readlimit);
    }

    @Override
    public synchronized void reset() throws IOException {
        abortIfNeeded();
        in.reset();
    }

    @Override
    public boolean markSupported() {
        abortIfNeeded();
        return in.markSupported();
    }

    public void release() {
        if (in != null) {
            try {
                in.close();
            } catch (IOException ex) {
                // Ignore exception.
            }
        }
    }
}
