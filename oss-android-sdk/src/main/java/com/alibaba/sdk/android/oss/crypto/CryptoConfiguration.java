package com.alibaba.sdk.android.oss.crypto;

import com.alibaba.sdk.android.oss.ClientConfiguration;

import java.security.Provider;
import java.security.SecureRandom;

public class CryptoConfiguration {
    private ContentCryptoMode contentCryptoMode;
    private SecureRandom secureRandom;
    private Provider contentCryptoProvider;

    public CryptoConfiguration() {
        contentCryptoMode = ContentCryptoMode.AES_CTR_MODE;
        secureRandom = new SecureRandom();
        contentCryptoProvider = null;
    }

    public ContentCryptoMode getContentCryptoMode() {
        return contentCryptoMode;
    }

    public void setContentCryptoMode(ContentCryptoMode contentCryptoMode) {
        this.contentCryptoMode = contentCryptoMode;
    }

    public SecureRandom getSecureRandom() {
        return secureRandom;
    }

    public void setSecureRandom(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    public Provider getContentCryptoProvider() {
        return contentCryptoProvider;
    }

    public void setContentCryptoProvider(Provider contentCryptoProvider) {
        this.contentCryptoProvider = contentCryptoProvider;
    }
}
