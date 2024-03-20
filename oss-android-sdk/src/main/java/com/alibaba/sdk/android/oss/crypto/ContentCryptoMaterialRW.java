package com.alibaba.sdk.android.oss.crypto;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.SecretKey;

/**
 * ContentCryptoMaterialRW has the setting accessor of {@link ContentCryptoMaterial}.
 */
public class ContentCryptoMaterialRW extends ContentCryptoMaterial {
    /**
     * Sets the content crypto algorithm to the specified algorithm.
     */
    public void setContentCryptoAlgorithm(String cententCryptoAlgorithm) {
        this.contentCryptoAlgorithm = cententCryptoAlgorithm;
    }

    /**
     * Sets the content encryption key to the specified key.
     */
    public void setCEK(SecretKey cek) {
        this.cek = cek;
    }

    /**
     * Sets the content crypto cipher start counter to the specified counter.
     */
    public void setIV(byte[] iv) {
        this.iv = iv;
    }

    /**
     * Sets the encrypted content encryption key to the specified array.
     */
    public void setEncryptedCEK(byte[] encryptedCEK) {
        this.encryptedCEK = encryptedCEK.clone();
    }

    /**
     * Sets the encrypted content crypto cipher start counter to the specified array.
     */
    public void setEncryptedIV(byte[] encryptedIV) {
        this.encryptedIV = encryptedIV.clone();
    }

    /**
     * Sets the key wrap algorithm to the specified algorithm.
     */
    public void setKeyWrapAlgorithm(String keyWrapAlgorithm) {
        this.keyWrapAlgorithm = keyWrapAlgorithm;
    }

    /**
     * Sets the description of the encryption materials
     */
    public void setMaterialsDescription(Map<String, String> matdesc) {
        this.matdesc = Collections.unmodifiableMap(new TreeMap<String, String>(matdesc));
    }
}
