package com.alibaba.sdk.android.oss.crypto;

import com.alibaba.sdk.android.oss.ClientException;

public interface EncryptionMaterials {
    /**
     * Encrypt the cek and iv and put the result into the given {@link ContentCryptoMaterialRW} instance.
     *
     * @param  contentMaterial
     *              The materials that contans the content crypto info.
     */
    public void encryptCEK(ContentCryptoMaterialRW contentMaterial) throws ClientException;

    /**
     * Decrypt the secured cek and secured iv and put the result into the given {@link ContentCryptoMaterialRW}
     * instance
     *
     * @param  contentMaterial
     *              The materials that contans the content crypto info.
     */
    public void decryptCEK(ContentCryptoMaterialRW contentMaterial) throws ClientException;
}
