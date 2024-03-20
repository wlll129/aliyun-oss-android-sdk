package com.alibaba.sdk.android;

import android.util.Pair;

import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.common.utils.BinaryUtil;
import com.alibaba.sdk.android.oss.crypto.AesCryptoScheme;
import com.alibaba.sdk.android.oss.crypto.ContentCryptoMaterial;
import com.alibaba.sdk.android.oss.crypto.ContentCryptoMaterialRW;
import com.alibaba.sdk.android.oss.crypto.ContentCryptoMode;
import com.alibaba.sdk.android.oss.crypto.SimpleRSAEncryptionMaterials;

import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static com.alibaba.sdk.android.oss.crypto.SimpleRSAEncryptionMaterials.KEY_WRAP_ALGORITHM;
import static org.junit.Assert.assertEquals;

public class OSSEncryptionMaterialsTest extends BaseTestCase {

    private final String PLAIN_TEXT = "kdnsknshiwonrjsn23e1vdjknvlsfnsl34ihsohnqm92u32jns.msl082mjk73643dns";
    private final AesCryptoScheme contentCryptoScheme = new AesCryptoScheme();

    private final String PUBLIC_KEY_PEM_XC509 =
            "-----BEGIN PUBLIC KEY-----\n"
                    + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIUc0RE+OF4qvJkFp/sBR4iiPy\n"
                    + "5czlKdHoOKOjhvh93aGpipoMb05+t07XSOBDJUzKGhqqVQJZEQahKXJUU0h3mxYy\n"
                    + "xRQMhhWWWdH1LH4s/GAjf4h5l+6tKxS6mnZGH4IlbJz1pvbPiZjzD6BEWtGBMAxZ\n" + "IjqPgSRjJpB6fBIrHQIDAQAB\n"
                    + "-----END PUBLIC KEY-----";

    private static String PRIVATE_KEY_PEM_PKCS8 =
            "-----BEGIN PRIVATE KEY-----\n"
                    + "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMhRzRET44Xiq8mQ\n"
                    + "Wn+wFHiKI/LlzOUp0eg4o6OG+H3doamKmgxvTn63TtdI4EMlTMoaGqpVAlkRBqEp\n"
                    + "clRTSHebFjLFFAyGFZZZ0fUsfiz8YCN/iHmX7q0rFLqadkYfgiVsnPWm9s+JmPMP\n"
                    + "oERa0YEwDFkiOo+BJGMmkHp8EisdAgMBAAECgYAbuSZ2TJhaeSppNO8xaL8Mh6G+\n"
                    + "Bgu7U3RXfS84fH97e+bZvfLf8a+dXeUtakqPQGRGPCKgnC89AFw4hbHq9bO7iygc\n"
                    + "0j57UVMmAURN9azX4cA+BH0am1sMkZ1UdziLzkkH6cq9u4Sab+SrTGZ1Dc55JWpm\n"
                    + "rJ+WYZOdwIxQArlYAQJBAOkHCzd4NrvDhKtnKiYwyK/RRboZhZZfGe9JXMrYDnkB\n"
                    + "CJKh6NTZE+FnosnO6+vYx7P2XuY6/KIm+91xo7pRrB0CQQDcEUzbPzabdD15g9J6\n"
                    + "AHaScIC4pONlmYMu3sht3/PUqB0qve2nNG1Y2XGpLSX1uw3v0h9LAbDBsUWGJBKt\n"
                    + "ZEsBAkAmz2CD3YaoIPkgnu77K1bRSXZmd0ezcqVcIAjPU8qdRpnJ6iNgB8Ny4BLR\n"
                    + "r5/FSPaBt3+4soxO6VU7XWjaaC3VAkEAkFtQ3Sk0OvkfMkzEjn8rSJg/999Bw23V\n"
                    + "3bMKKvkTS1YT++umr132tKe+pUkWc4EGfWCKYntzZTtR7dJP5im6AQJBAMZIDGwt\n"
                    + "pIYUt9sE4rMzuym/dy/Nru9gGSx9HrFPopFpRGHrJoaaQryB+auQUy1ZDQILd815\n" + "x7BQ0ulJy4q6cKE=\n"
                    + "-----END PRIVATE KEY-----";

    @Override
    void initTestData() throws Exception {

    }

    @Test
    public void testUsePrivateKeyPKCS8() throws Exception {
        final RSAPrivateKey privateKey = SimpleRSAEncryptionMaterials.getPrivateKeyFromPemPKCS8(PRIVATE_KEY_PEM_PKCS8);
        final RSAPublicKey publicKey = SimpleRSAEncryptionMaterials.getPublicKeyFromPemX509(PUBLIC_KEY_PEM_XC509);

        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        byte[] encryptedData = encrypt(keyPair.getPublic(), PLAIN_TEXT.getBytes());
        byte[] decryptedData = decrypt(keyPair.getPrivate(), encryptedData);
        String decryptedStr = new String(decryptedData);
        assertEquals(PLAIN_TEXT, decryptedStr);
    }

    @Test
    public void testUsePrivateKeyPKCS1AndPKCS8() throws Exception {
        final RSAPublicKey publicKey = SimpleRSAEncryptionMaterials.getPublicKeyFromPemX509(PUBLIC_KEY_PEM_XC509);
        final RSAPrivateKey privateKeyPKCS8 = SimpleRSAEncryptionMaterials.getPrivateKeyFromPemPKCS8(PRIVATE_KEY_PEM_PKCS8);

        // encrypt by public key
        byte[] encryptedData = encrypt(publicKey, PLAIN_TEXT.getBytes());

        // decrypt by private key pkcs8
        byte[] decryptedData = decrypt(privateKeyPKCS8, encryptedData);
        String decryptedStrPKCS8 = new String(decryptedData);
        assertEquals(PLAIN_TEXT, decryptedStrPKCS8);
    }

    @Test
    public void TestEncryptContentCryptoMaterialRW() throws Exception {
        final RSAPublicKey publicKey = SimpleRSAEncryptionMaterials.getPublicKeyFromPemX509(PUBLIC_KEY_PEM_XC509);
        final RSAPrivateKey privateKeyPKCS8 = SimpleRSAEncryptionMaterials.getPrivateKeyFromPemPKCS8(PRIVATE_KEY_PEM_PKCS8);
        KeyPair keyPair = new KeyPair(publicKey, privateKeyPKCS8);
        Map<String, String> desc = new HashMap<String, String>();

        SimpleRSAEncryptionMaterials encryptionMaterials = new SimpleRSAEncryptionMaterials(keyPair, desc);

        ContentCryptoMaterialRW contentCryptoMaterial = new ContentCryptoMaterialRW();
        contentCryptoMaterial.setCEK(generateCEK());
        contentCryptoMaterial.setIV(generateIV());
        contentCryptoMaterial.setContentCryptoAlgorithm(contentCryptoScheme.getContentChiperAlgorithm());
        contentCryptoMaterial.setKeyWrapAlgorithm(contentCryptoScheme.getKeyGeneratorAlgorithm());
        contentCryptoMaterial.setMaterialsDescription(desc);

        encryptionMaterials.encryptCEK(contentCryptoMaterial);

        byte[] cek = contentCryptoMaterial.getCEK().getEncoded();
        byte[] iv = contentCryptoMaterial.getIV();

        ContentCryptoMaterialRW encryptedContentMaterial = new ContentCryptoMaterialRW();
        encryptedContentMaterial.setEncryptedCEK(contentCryptoMaterial.getEncryptedCEK());
        encryptedContentMaterial.setEncryptedIV(contentCryptoMaterial.getEncryptedIV());
        encryptedContentMaterial.setContentCryptoAlgorithm(contentCryptoMaterial.getContentCryptoAlgorithm());
        encryptedContentMaterial.setKeyWrapAlgorithm(contentCryptoMaterial.getKeyWrapAlgorithm());
        encryptedContentMaterial.setMaterialsDescription(desc);

        encryptionMaterials.decryptCEK(encryptedContentMaterial);

        assertEquals(BinaryUtil.calculateBase64Md5(cek), BinaryUtil.calculateBase64Md5(encryptedContentMaterial.getCEK().getEncoded()));
        assertEquals(BinaryUtil.calculateBase64Md5(iv), BinaryUtil.calculateBase64Md5(encryptedContentMaterial.getIV()));
    }

    @Test
    public void testTestEncryptContentMaterialWithMultipleMaterials() throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair keyPair1 = keyGenerator.generateKeyPair();
        Map<String, String> desc1 = new HashMap<String, String>();
        desc1.put("key1", "value1");

        SimpleRSAEncryptionMaterials encryptionMaterials = new SimpleRSAEncryptionMaterials(keyPair1, desc1);

        keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(1024);
        KeyPair keyPair2 = keyGenerator.generateKeyPair();
        Map<String, String> desc2 = new HashMap<String, String>();
        desc2.put("key2", "value2");

        encryptionMaterials.addKeyPairDescMaterial(keyPair2, desc2);


        ContentCryptoMaterialRW contentCryptoMaterial = new ContentCryptoMaterialRW();
        contentCryptoMaterial.setCEK(generateCEK());
        contentCryptoMaterial.setIV(generateIV());
        contentCryptoMaterial.setContentCryptoAlgorithm(contentCryptoScheme.getContentChiperAlgorithm());
        contentCryptoMaterial.setKeyWrapAlgorithm(KEY_WRAP_ALGORITHM);
        contentCryptoMaterial.setMaterialsDescription(desc1);

        byte[] cek = contentCryptoMaterial.getCEK().getEncoded();
        byte[] iv = contentCryptoMaterial.getIV();

        encryptionMaterials.encryptCEK(contentCryptoMaterial);

        byte[] decryptedCek = decrypt(keyPair1.getPrivate(), contentCryptoMaterial.getEncryptedCEK());
        byte[] decryptedIV = decrypt(keyPair1.getPrivate(), contentCryptoMaterial.getEncryptedIV());

        assertEquals(BinaryUtil.calculateBase64Md5(decryptedCek), BinaryUtil.calculateBase64Md5(cek));
        assertEquals(BinaryUtil.calculateBase64Md5(decryptedIV), BinaryUtil.calculateBase64Md5(iv));

        cek = generateCEK().getEncoded();
        iv = generateIV();

        byte[] encryptedCek = encrypt(keyPair2.getPublic(), cek);
        byte[] encryptedIV = encrypt(keyPair2.getPublic(), iv);

        contentCryptoMaterial = new ContentCryptoMaterialRW();
        contentCryptoMaterial.setEncryptedCEK(encryptedCek);
        contentCryptoMaterial.setEncryptedIV(encryptedIV);
        contentCryptoMaterial.setContentCryptoAlgorithm(contentCryptoScheme.getContentChiperAlgorithm());
        contentCryptoMaterial.setKeyWrapAlgorithm(KEY_WRAP_ALGORITHM);
        contentCryptoMaterial.setMaterialsDescription(desc2);

        encryptionMaterials.decryptCEK(contentCryptoMaterial);

        assertEquals(BinaryUtil.calculateBase64Md5(contentCryptoMaterial.getCEK().getEncoded()), BinaryUtil.calculateBase64Md5(cek));
        assertEquals(BinaryUtil.calculateBase64Md5(contentCryptoMaterial.getIV()), BinaryUtil.calculateBase64Md5(iv));

    }

    private byte[] encrypt(PublicKey publicKey, byte[] plainData) throws Exception {
        if (publicKey == null) {
            throw new Exception("public key is null.");
        }

        Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] output = cipher.doFinal(plainData);
        return output;
    }

    private byte[] decrypt(PrivateKey privateKey, byte[] cipherData) throws Exception {
        if (privateKey == null) {
            throw new Exception("private key is null.");
        }
        Cipher cipher = null;
        cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] output = cipher.doFinal(cipherData);
        return output;
    }

    private SecretKey generateCEK() throws ClientException {
        KeyGenerator generator;
        final String keygenAlgo = contentCryptoScheme.getKeyGeneratorAlgorithm();
        final int keyLength = contentCryptoScheme.getKeyLengthInBits();
        try {
            generator = KeyGenerator.getInstance(keygenAlgo);
            generator.init(keyLength, new SecureRandom());
            SecretKey secretKey = generator.generateKey();
            for (int retry = 0; retry < 9; retry++) {
                secretKey = generator.generateKey();
                if (secretKey.getEncoded()[0] != 0)
                    return secretKey;
            }
            throw new ClientException("Failed to generate secret key");
        } catch (NoSuchAlgorithmException e) {
            throw new ClientException("No such algorithm:" + keygenAlgo + ", " + e.getMessage(), e);
        }
    }

    private byte[] generateIV() {
        final byte[] iv = new byte[contentCryptoScheme.getContentChiperIVLength()];
        new SecureRandom().nextBytes(iv);
        for (int i = 8; i < 12; i++) {
            iv[i] = 0;
        }
        return iv;
    }

}
