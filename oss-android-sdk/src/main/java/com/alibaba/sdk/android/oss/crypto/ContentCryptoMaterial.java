package com.alibaba.sdk.android.oss.crypto;

import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

import javax.crypto.SecretKey;

public class ContentCryptoMaterial implements Serializable {

    /**Prevent sensitive information serializing.*/
    protected transient SecretKey cek;
    /**Prevent sensitive information serializing.*/
    protected transient byte[] iv;
    protected String contentCryptoAlgorithm;
    protected byte[] encryptedCEK;
    protected byte[] encryptedIV;
    protected String keyWrapAlgorithm;
    protected Map<String, String> matdesc;

    protected ContentCryptoMaterial() {
    };

    public ContentCryptoMaterial(SecretKey cek,
                                 byte[] iv,
                                 String contentCryptoAlgorithm,
                                 byte[] encryptedCEK,
                                 byte[] encryptedIV,
                                 String keyWrapAlgorithm,
                                 Map<String, String>matDesc) {
        this.cek = cek;
        this.iv = iv.clone();
        this.contentCryptoAlgorithm = contentCryptoAlgorithm;
        this.encryptedCEK = encryptedCEK.clone();
        this.encryptedIV = encryptedIV.clone();
        this.keyWrapAlgorithm = keyWrapAlgorithm;
        this.matdesc = Collections.unmodifiableMap(new TreeMap<String, String>(matDesc));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;

        if (cek != null) {
            for (int i=0; i<cek.getEncoded().length; i++){
                result = prime * result + cek.getEncoded()[i];
            }
        }

        if (iv != null) {
            for (int i=0; i<iv.length; i++){
                result = prime * result + iv[i];
            }
        }

        if (encryptedCEK != null) {
            for (int i=0; i<encryptedCEK.length; i++){
                result = prime * result + encryptedCEK[i];
            }
        }

        if (encryptedIV != null) {
            for (int i=0; i<encryptedIV.length; i++){
                result = prime * result + encryptedIV[i];
            }
        }

        result = prime * result + ((contentCryptoAlgorithm == null) ? 0 : contentCryptoAlgorithm.hashCode());
        result = prime * result + ((keyWrapAlgorithm == null) ? 0 : keyWrapAlgorithm.hashCode());
        result = prime * result + ((matdesc == null) ? 0 : matdesc.hashCode());
        return result;
    }

    /**
     * @return the content crypto algorithm name.
     */
    public String getContentCryptoAlgorithm() {
        return contentCryptoAlgorithm;
    }

    /**
     * @return the content encryption key.
     */
    public SecretKey getCEK() {
        return cek;
    }

    /**
     * @return an array of bytes representing the content crypto cipher start counter.
     */
    public byte[] getIV() {
        return iv.clone();
    }

    /**
     * @return an array of bytes representing the encrypted content encrytion key.
     */
    public byte[] getEncryptedCEK() {
        return encryptedCEK.clone();
    }

    /**
     * @return an array of bytes representing the encrypted IV.
     */
    public byte[] getEncryptedIV() {
        return encryptedIV.clone();
    }

    /**
     * @return the algorithm that it wraps content encrypt key(cek) to encrypted cek.
     */
    public String getKeyWrapAlgorithm() {
        return keyWrapAlgorithm;
    }

    /**
     * @return the description of the encryption materials
     */
    public Map<String, String> getMaterialsDescription() {
        return matdesc;
    }
}
