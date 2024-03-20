package com.alibaba.sdk.android.oss.crypto;

import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.ServiceException;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.internal.OSSAsyncTask;
import com.alibaba.sdk.android.oss.model.GetObjectRequest;
import com.alibaba.sdk.android.oss.model.GetObjectResult;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadResult;
import com.alibaba.sdk.android.oss.model.ObjectMetadata;
import com.alibaba.sdk.android.oss.model.PutObjectRequest;
import com.alibaba.sdk.android.oss.model.PutObjectResult;
import com.alibaba.sdk.android.oss.model.UploadPartRequest;
import com.alibaba.sdk.android.oss.model.UploadPartResult;

public interface CryptoModule {
    public PutObjectResult putObjectSecurely(PutObjectRequest req) throws ClientException, ServiceException;
    public OSSAsyncTask<PutObjectResult> asyncPutObjectSecurely(PutObjectRequest request, OSSCompletedCallback<PutObjectRequest, PutObjectResult> completedCallback);

    public GetObjectResult getObjectSecurely(GetObjectRequest req) throws ClientException, ServiceException;
    public OSSAsyncTask<GetObjectResult> asyncGetObjectSecurely(GetObjectRequest request, OSSCompletedCallback<GetObjectRequest, GetObjectResult> completedCallback);

//    public ObjectMetadata getObjectSecurely(GetObjectRequest req, File file);

    public InitiateMultipartUploadResult initiateMultipartUploadSecurely(InitiateMultipartUploadRequest request, MultipartUploadCryptoContext context) throws ClientException, ServiceException;
    public OSSAsyncTask<InitiateMultipartUploadResult> asyncInitMultipartUploadSecurely(InitiateMultipartUploadRequest request, MultipartUploadCryptoContext context, OSSCompletedCallback<InitiateMultipartUploadRequest, InitiateMultipartUploadResult> completedCallback);

    public UploadPartResult uploadPartSecurely(UploadPartRequest request, MultipartUploadCryptoContext context) throws ClientException;
    public OSSAsyncTask<UploadPartResult> asyncUploadPartSecurely(UploadPartRequest request, MultipartUploadCryptoContext context, OSSCompletedCallback<UploadPartRequest, UploadPartResult> completedCallback);

}
