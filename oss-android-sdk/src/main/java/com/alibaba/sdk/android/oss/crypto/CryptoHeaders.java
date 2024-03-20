package com.alibaba.sdk.android.oss.crypto;

public interface CryptoHeaders {
    public static String CRYPTO_KEY = "x-oss-meta-client-side-encryption-key";
    public static String CRYPTO_IV = "x-oss-meta-client-side-encryption-start";
    public static String CRYPTO_CEK_ALG = "x-oss-meta-client-side-encryption-cek-alg";
    public static String CRYPTO_WRAP_ALG = "x-oss-meta-client-side-encryption-wrap-alg";
    public static String CRYPTO_MATDESC = "x-oss-meta-client-side-encryption-matdesc";
    public static String CRYPTO_DATA_SIZE = "x-oss-meta-client-side-encryption-data-size";
    public static String CRYPTO_PART_SIZE = "x-oss-meta-client-side-encryption-part-size";
    public static String CRYPTO_UNENCRYPTION_CONTENT_LENGTH = "x-oss-meta-client-side-encryption-unencrypted-content-length";
    public static String CRYPTO_UNENCRYPTION_CONTENT_MD5 = "x-oss-meta-client-side-encryption-unencrypted-content-md5";
}
