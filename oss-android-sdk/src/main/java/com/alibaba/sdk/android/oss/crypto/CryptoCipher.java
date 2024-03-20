package com.alibaba.sdk.android.oss.crypto;

import com.alibaba.sdk.android.oss.ClientException;

import java.security.Provider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class CryptoCipher {

    private final Cipher cipher;
    private final CryptoScheme scheme;
    private final SecretKey secreteKey;
    private final int cipherMode;

    CryptoCipher(Cipher cipher, CryptoScheme scheme, SecretKey secreteKey, int cipherMode) {
        this.cipher = cipher;
        this.scheme = scheme;
        this.secreteKey = secreteKey;
        this.cipherMode = cipherMode;
    }

    CryptoCipher(SecretKey cek, byte[] iv, int cipherMode, CryptoScheme scheme, Provider provider) throws ClientException {
        try {
            Cipher cipher = null;
            if (provider != null) {
                cipher = Cipher.getInstance(scheme.getContentChiperAlgorithm(), provider);
            } else {
                cipher = Cipher.getInstance(scheme.getContentChiperAlgorithm());
            }
            cipher.init(cipherMode, cek, new IvParameterSpec(iv));
            this.cipher = cipher;
            this.scheme = scheme;
            this.secreteKey = cek;
            this.cipherMode = cipherMode;
        } catch (Exception e) {
            throw new ClientException("Unable to build cipher: " + e.getMessage(), e);
        }
    }

    /**
     * Recreates a new instance of CipherLite from the current one.
     */
    CryptoCipher recreate() throws ClientException {
        return new CryptoCipher(secreteKey, cipher.getIV(), this.cipherMode, this.scheme, cipher.getProvider());
    }

    byte[] doFinal() throws IllegalBlockSizeException, BadPaddingException {
        return cipher.doFinal();
    }

    /**
     * Continues a multiple-part encryption or decryption operation (depending on
     * how the underlying cipher was initialized), processing another data part.
     *
     * <p>
     * The first <code>inputLen</code> bytes in the <code>input</code> buffer,
     * starting at <code>inputOffset</code> inclusive, are processed, and the result
     * is stored in a new buffer.
     *
     * <p>
     * If <code>inputLen</code> is zero, this method returns <code>null</code>.
     *
     * @param input
     *            the input buffer
     * @param inputOffset
     *            the offset in <code>input</code> where the input starts
     * @param inputLen
     *            the input length
     *
     * @return the new buffer with the result, or null if the underlying cipher is a
     *         block cipher and the input data is too short to result in a new
     *         block.
     *
     * @exception IllegalStateException
     *                if the underlying cipher is in a wrong state (e.g., has
     *                not been initialized)
     */
    byte[] update(byte[] input, int inputOffset, int inputLen) {
        return cipher.update(input, inputOffset, inputLen);
    }
}
