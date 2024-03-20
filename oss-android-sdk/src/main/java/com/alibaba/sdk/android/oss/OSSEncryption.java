package com.alibaba.sdk.android.oss;

import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.crypto.MultipartUploadCryptoContext;
import com.alibaba.sdk.android.oss.internal.OSSAsyncTask;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadResult;
import com.alibaba.sdk.android.oss.model.UploadPartRequest;
import com.alibaba.sdk.android.oss.model.UploadPartResult;

public interface OSSEncryption extends OSS {

    public InitiateMultipartUploadResult initMultipartUpload(InitiateMultipartUploadRequest request, MultipartUploadCryptoContext context) throws ClientException, ServiceException;

    public OSSAsyncTask<InitiateMultipartUploadResult> asyncInitMultipartUpload(InitiateMultipartUploadRequest request, MultipartUploadCryptoContext context, OSSCompletedCallback<InitiateMultipartUploadRequest, InitiateMultipartUploadResult> completedCallback);

    public UploadPartResult uploadPart(UploadPartRequest request, MultipartUploadCryptoContext context) throws ClientException, ServiceException;

    public OSSAsyncTask<UploadPartResult> asyncUploadPart(UploadPartRequest request, MultipartUploadCryptoContext context, OSSCompletedCallback<UploadPartRequest, UploadPartResult> completedCallback);

    @Override
    @Deprecated
    InitiateMultipartUploadResult initMultipartUpload(InitiateMultipartUploadRequest request) throws ClientException, ServiceException;

    @Override
    @Deprecated
    OSSAsyncTask<InitiateMultipartUploadResult> asyncInitMultipartUpload(InitiateMultipartUploadRequest request, OSSCompletedCallback<InitiateMultipartUploadRequest, InitiateMultipartUploadResult> completedCallback);

    @Override
    @Deprecated
    UploadPartResult uploadPart(UploadPartRequest request) throws ClientException, ServiceException;

    @Override
    @Deprecated
    OSSAsyncTask<UploadPartResult> asyncUploadPart(UploadPartRequest request, OSSCompletedCallback<UploadPartRequest, UploadPartResult> completedCallback);
}
