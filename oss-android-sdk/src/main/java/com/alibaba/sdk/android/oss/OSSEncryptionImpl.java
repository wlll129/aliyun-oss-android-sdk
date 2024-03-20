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
import com.alibaba.sdk.android.oss.internal.EncryptedExtensionRequestOperation;
import com.alibaba.sdk.android.oss.internal.EncryptedInternalRequestOperation;
import com.alibaba.sdk.android.oss.internal.OSSAsyncTask;
import com.alibaba.sdk.android.oss.model.EncryptedPutObjectRequest;
import com.alibaba.sdk.android.oss.model.GetObjectRequest;
import com.alibaba.sdk.android.oss.model.GetObjectResult;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadResult;
import com.alibaba.sdk.android.oss.model.PutObjectRequest;
import com.alibaba.sdk.android.oss.model.PutObjectResult;
import com.alibaba.sdk.android.oss.model.ResumableUploadRequest;
import com.alibaba.sdk.android.oss.model.ResumableUploadResult;
import com.alibaba.sdk.android.oss.model.UploadPartRequest;
import com.alibaba.sdk.android.oss.model.UploadPartResult;

public class OSSEncryptionImpl extends OSSImpl implements OSSEncryption {

    private EncryptionMaterials encryptionMaterials;
    private CryptoConfiguration cryptoConfiguration;
    private Context context;
    private final OSSDirect ossDirect = new OSSEncryptionImpl.OSSDirectImpl();


    public OSSEncryptionImpl(Context context, String endpoint, OSSCredentialProvider credentialProvider, ClientConfiguration conf,
                             EncryptionMaterials encryptionMaterials, CryptoConfiguration cryptoConfig) {
        super(context, endpoint, credentialProvider, conf);

        this.internalRequestOperation = new EncryptedInternalRequestOperation(context, endpointURI, credentialProvider, conf);
        this.extensionRequestOperation = new EncryptedExtensionRequestOperation(internalRequestOperation, this);

        this.encryptionMaterials = encryptionMaterials;
        this.cryptoConfiguration = cryptoConfig;
        this.context = context;
    }

    public OSSEncryptionImpl(Context context, OSSCredentialProvider credentialProvider, ClientConfiguration conf,
                             EncryptionMaterials encryptionMaterials, CryptoConfiguration cryptoConfig) {
        super(context, credentialProvider, conf);

        this.internalRequestOperation = new EncryptedInternalRequestOperation(context, endpointURI, credentialProvider, conf);

        this.encryptionMaterials = encryptionMaterials;
        this.cryptoConfiguration = cryptoConfig;
        this.context = context;
    }

    @Override
    public PutObjectResult putObject(PutObjectRequest request) throws ClientException, ServiceException {
        CryptoModule cryptoModule = CryptoModuleBase.getCryptoModuleBase(ossDirect, ContentCryptoMode.AES_CTR_MODE, encryptionMaterials, cryptoConfiguration, context);
        return cryptoModule.putObjectSecurely(request);
    }

    @Override
    public OSSAsyncTask<PutObjectResult> asyncPutObject(PutObjectRequest request, OSSCompletedCallback<PutObjectRequest, PutObjectResult> completedCallback) {
        CryptoModule cryptoModule = CryptoModuleBase.getCryptoModuleBase(ossDirect, ContentCryptoMode.AES_CTR_MODE, encryptionMaterials, cryptoConfiguration, context);
        return cryptoModule.asyncPutObjectSecurely(request, completedCallback);
    }

    @Override
    public GetObjectResult getObject(GetObjectRequest request) throws ClientException, ServiceException {
        CryptoModule cryptoModule = CryptoModuleBase.getCryptoModuleBase(ossDirect, ContentCryptoMode.AES_CTR_MODE, encryptionMaterials, cryptoConfiguration, context);
        return cryptoModule.getObjectSecurely(request);
    }

    @Override
    public OSSAsyncTask<GetObjectResult> asyncGetObject(GetObjectRequest request, OSSCompletedCallback<GetObjectRequest, GetObjectResult> completedCallback) {
        CryptoModule cryptoModule = CryptoModuleBase.getCryptoModuleBase(ossDirect, ContentCryptoMode.AES_CTR_MODE, encryptionMaterials, cryptoConfiguration, context);
        return cryptoModule.asyncGetObjectSecurely(request, completedCallback);
    }

    @Override
    public InitiateMultipartUploadResult initMultipartUpload(InitiateMultipartUploadRequest request, MultipartUploadCryptoContext context) throws ClientException, ServiceException {
        CryptoModule cryptoModule = CryptoModuleBase.getCryptoModuleBase(ossDirect, ContentCryptoMode.AES_CTR_MODE, encryptionMaterials, cryptoConfiguration, this.context);
        return cryptoModule.initiateMultipartUploadSecurely(request, context);
    }

    @Override
    public OSSAsyncTask<InitiateMultipartUploadResult> asyncInitMultipartUpload(InitiateMultipartUploadRequest request, MultipartUploadCryptoContext context, OSSCompletedCallback<InitiateMultipartUploadRequest, InitiateMultipartUploadResult> completedCallback) {
        CryptoModule cryptoModule = CryptoModuleBase.getCryptoModuleBase(ossDirect, ContentCryptoMode.AES_CTR_MODE, encryptionMaterials, cryptoConfiguration, this.context);
        return cryptoModule.asyncInitMultipartUploadSecurely(request, context, completedCallback);
    }

    @Override
    public UploadPartResult uploadPart(UploadPartRequest request, MultipartUploadCryptoContext context) throws ClientException, ServiceException {
        CryptoModule cryptoModule = CryptoModuleBase.getCryptoModuleBase(ossDirect, ContentCryptoMode.AES_CTR_MODE, encryptionMaterials, cryptoConfiguration, this.context);
        return cryptoModule.uploadPartSecurely(request, context);
    }

    @Override
    public OSSAsyncTask<UploadPartResult> asyncUploadPart(UploadPartRequest request, MultipartUploadCryptoContext context, OSSCompletedCallback<UploadPartRequest, UploadPartResult> completedCallback) {
        CryptoModule cryptoModule = CryptoModuleBase.getCryptoModuleBase(ossDirect, ContentCryptoMode.AES_CTR_MODE, encryptionMaterials, cryptoConfiguration, this.context);
        return cryptoModule.asyncUploadPartSecurely(request, context, completedCallback);
    }

    private final class OSSDirectImpl implements OSSDirect {

        @Override
        public ClientConfiguration getInnerClientConfiguration() {
            return null;
        }

        @Override
        public PutObjectResult putObject(PutObjectRequest req) throws ClientException, ServiceException {
            return OSSEncryptionImpl.super.putObject(req);
        }

        @Override
        public OSSAsyncTask<PutObjectResult> asyncPutObject(PutObjectRequest request, OSSCompletedCallback<PutObjectRequest, PutObjectResult> completedCallback) {
            return OSSEncryptionImpl.super.asyncPutObject(request, completedCallback);
        }

        @Override
        public GetObjectResult getObject(GetObjectRequest req) throws ClientException, ServiceException {
            return OSSEncryptionImpl.super.getObject(req);
        }

        @Override
        public OSSAsyncTask<GetObjectResult> asyncGetObject(GetObjectRequest request, OSSCompletedCallback<GetObjectRequest, GetObjectResult> completedCallback) {
            return OSSEncryptionImpl.super.asyncGetObject(request, completedCallback);
        }

        @Override
        public InitiateMultipartUploadResult initMultipartUpload(InitiateMultipartUploadRequest request) throws ClientException, ServiceException {
            return OSSEncryptionImpl.super.initMultipartUpload(request);
        }

        @Override
        public OSSAsyncTask<InitiateMultipartUploadResult> asyncInitMultipartUpload(InitiateMultipartUploadRequest request, OSSCompletedCallback<InitiateMultipartUploadRequest, InitiateMultipartUploadResult> completedCallback) {
            return OSSEncryptionImpl.super.asyncInitMultipartUpload(request, completedCallback);
        }

        @Override
        public UploadPartResult uploadPart(UploadPartRequest request) throws ClientException, ServiceException {
            return OSSEncryptionImpl.super.uploadPart(request);
        }

        @Override
        public OSSAsyncTask<UploadPartResult> asyncUploadPart(UploadPartRequest request, OSSCompletedCallback<UploadPartRequest, UploadPartResult> completedCallback) {
            return OSSEncryptionImpl.super.asyncUploadPart(request, completedCallback);
        }
    }
}
