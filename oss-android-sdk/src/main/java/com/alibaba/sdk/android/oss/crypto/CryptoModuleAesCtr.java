package com.alibaba.sdk.android.oss.crypto;

import android.content.Context;

import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.model.Range;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class CryptoModuleAesCtr extends CryptoModuleBase {
    public CryptoModuleAesCtr(OSSDirect direct, EncryptionMaterials encryptionMaterials, CryptoConfiguration cryptoConfig, Context context) {
        super(direct, encryptionMaterials, cryptoConfig, context);
    }

    /**
     * @return an array of bytes representing the content crypto cipher start counter.
     */
    @Override
    final byte[] generateIV() {
        final byte[] iv = new byte[contentCryptoScheme.getContentChiperIVLength()];
        cryptoConfig.getSecureRandom().nextBytes(iv);
        if (cryptoConfig.getContentCryptoMode().equals(ContentCryptoMode.AES_CTR_MODE)) {
            for (int i = 8; i < 12; i++) {
                iv[i] = 0;
            }
        }
        return iv;
    }

    @Override
    CryptoCipher createCryptoCipherFromContentMaterial(ContentCryptoMaterial cekMaterial, int cipherMode, Range cryptoRange, long skipBlock) throws ClientException {
        if (cipherMode != Cipher.ENCRYPT_MODE && cipherMode != Cipher.DECRYPT_MODE) {
            throw new ClientException("Invalid cipher mode.");
        }
        byte[] iv = cekMaterial.getIV();
        SecretKey cek = cekMaterial.getCEK();
        String cekAlgo = cekMaterial.getContentCryptoAlgorithm();
        CryptoScheme tmpContentCryptoScheme = CryptoScheme.fromCEKAlgo(cekAlgo);
        // Adjust the IV if needed
        boolean isRangeGet = (cryptoRange != null);
        if (isRangeGet) {
            iv = tmpContentCryptoScheme.adjustIV(iv, cryptoRange.getBegin());
        } else if (skipBlock > 0) {
            iv = CryptoScheme.incrementBlocks(iv, skipBlock);
        }
        return new CryptoCipher(cek, iv, cipherMode, tmpContentCryptoScheme, cryptoConfig.getContentCryptoProvider());
    }

    /**
     *Creates a cipher from a {@link ContentCryptoMaterial} instance, it used to encrypt/decrypt data.
     *
     * @param cekMaterial
     *             It provides the cek iv and crypto algorithm to build an crypto cipher.
     * @param cipherMode
     *             Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param cryptoRange
     *             The first element of the crypto range is the offset of the acquired object,
     *             and it should be allgned with cipher block if it was not null.
     * @param skipBlock
     *              the number of blocks should be skiped when the cipher created.
     * @return a {@link CryptoCipher} instance for encrypt/decrypt data.
     */
    final CryptoCipher createCryptoCipherFromContentMaterial(ContentCryptoMaterial cekMaterial, int cipherMode,
                                                             long[] cryptoRange, long skipBlock) throws ClientException {
        if (cipherMode != Cipher.ENCRYPT_MODE && cipherMode != Cipher.DECRYPT_MODE) {
            throw new ClientException("Invalid cipher mode.");
        }
        byte[] iv = cekMaterial.getIV();
        SecretKey cek = cekMaterial.getCEK();
        String cekAlgo = cekMaterial.getContentCryptoAlgorithm();
        CryptoScheme tmpContentCryptoScheme = CryptoScheme.fromCEKAlgo(cekAlgo);
        // Adjust the IV if needed
        boolean isRangeGet = (cryptoRange != null);
        if (isRangeGet) {
            iv = tmpContentCryptoScheme.adjustIV(iv, cryptoRange[0]);
        } else if (skipBlock > 0) {
            iv = CryptoScheme.incrementBlocks(iv, skipBlock);
        }
        return new CryptoCipher(cek, iv, cipherMode, tmpContentCryptoScheme, cryptoConfig.getContentCryptoProvider());
    }
}
