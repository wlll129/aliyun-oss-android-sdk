package com.alibaba.sdk.android.oss;

import android.content.Context;

import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.common.auth.OSSCredentialProvider;
import com.alibaba.sdk.android.oss.crypto.ContentCryptoMode;
import com.alibaba.sdk.android.oss.crypto.CryptoConfiguration;
import com.alibaba.sdk.android.oss.crypto.CryptoModule;
import com.alibaba.sdk.android.oss.crypto.CryptoModuleBase;
import com.alibaba.sdk.android.oss.crypto.EncryptionMaterials;
import com.alibaba.sdk.android.oss.crypto.MultipartUploadCryptoContext;
import com.alibaba.sdk.android.oss.crypto.OSSDirect;
import com.alibaba.sdk.android.oss.internal.OSSAsyncTask;
import com.alibaba.sdk.android.oss.model.GetObjectRequest;
import com.alibaba.sdk.android.oss.model.GetObjectResult;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadResult;
import com.alibaba.sdk.android.oss.model.PutObjectRequest;
import com.alibaba.sdk.android.oss.model.PutObjectResult;
import com.alibaba.sdk.android.oss.model.UploadPartRequest;
import com.alibaba.sdk.android.oss.model.UploadPartResult;

public class OSSEncryptionClient extends OSSClient implements OSSEncryption {

    public OSSEncryptionClient(Context context, String endpoint, OSSCredentialProvider credsProvider, ClientConfiguration clientConfig,
                               EncryptionMaterials encryptionMaterials, CryptoConfiguration cryptoConfig) {
        super(context, endpoint, credsProvider, clientConfig);
        this.mOss = new OSSEncryptionImpl(context, endpoint, credsProvider, clientConfig, encryptionMaterials, cryptoConfig);
    }

    public OSSEncryptionClient(Context context, OSSCredentialProvider credentialProvider, ClientConfiguration conf, EncryptionMaterials encryptionMaterials, CryptoConfiguration cryptoConfig) {
        super(context, credentialProvider, conf);
        this.mOss = new OSSEncryptionImpl(context, credentialProvider, conf, encryptionMaterials, cryptoConfig);
    }

    @Override
    public InitiateMultipartUploadResult initMultipartUpload(InitiateMultipartUploadRequest request, MultipartUploadCryptoContext context) throws ClientException, ServiceException {
        return ((OSSEncryptionImpl)mOss).initMultipartUpload(request, context);
    }

    @Override
    public OSSAsyncTask<InitiateMultipartUploadResult> asyncInitMultipartUpload(InitiateMultipartUploadRequest request, MultipartUploadCryptoContext context, OSSCompletedCallback<InitiateMultipartUploadRequest, InitiateMultipartUploadResult> completedCallback) {
        return ((OSSEncryptionImpl)mOss).asyncInitMultipartUpload(request, context, completedCallback);
    }

    @Override
    public UploadPartResult uploadPart(UploadPartRequest request, MultipartUploadCryptoContext context) throws ClientException, ServiceException {
        return ((OSSEncryptionImpl)mOss).uploadPart(request, context);
    }

    @Override
    public OSSAsyncTask<UploadPartResult> asyncUploadPart(UploadPartRequest request, MultipartUploadCryptoContext context, OSSCompletedCallback<UploadPartRequest, UploadPartResult> completedCallback) {
        return ((OSSEncryptionImpl)mOss).asyncUploadPart(request, context, completedCallback);
    }
}
