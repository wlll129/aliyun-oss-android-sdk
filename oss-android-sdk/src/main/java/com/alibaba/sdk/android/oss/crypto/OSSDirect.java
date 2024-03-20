package com.alibaba.sdk.android.oss.crypto;

import com.alibaba.sdk.android.oss.ClientConfiguration;
import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.ServiceException;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.internal.OSSAsyncTask;
import com.alibaba.sdk.android.oss.model.GetObjectRequest;
import com.alibaba.sdk.android.oss.model.GetObjectResult;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadResult;
import com.alibaba.sdk.android.oss.model.PutObjectRequest;
import com.alibaba.sdk.android.oss.model.PutObjectResult;
import com.alibaba.sdk.android.oss.model.UploadPartRequest;
import com.alibaba.sdk.android.oss.model.UploadPartResult;

public interface OSSDirect {
    public ClientConfiguration getInnerClientConfiguration();

    public PutObjectResult putObject(PutObjectRequest req) throws ClientException, ServiceException;
    public OSSAsyncTask<PutObjectResult> asyncPutObject(PutObjectRequest request, OSSCompletedCallback<PutObjectRequest, PutObjectResult> completedCallback);

    public GetObjectResult getObject(GetObjectRequest req) throws ClientException, ServiceException;
    public OSSAsyncTask<GetObjectResult> asyncGetObject(GetObjectRequest request, OSSCompletedCallback<GetObjectRequest, GetObjectResult> completedCallback);

    public InitiateMultipartUploadResult initMultipartUpload(InitiateMultipartUploadRequest request)
            throws ClientException, ServiceException;
    public OSSAsyncTask<InitiateMultipartUploadResult> asyncInitMultipartUpload(InitiateMultipartUploadRequest request, OSSCompletedCallback<InitiateMultipartUploadRequest, InitiateMultipartUploadResult> completedCallback);

    public UploadPartResult uploadPart(UploadPartRequest request)
            throws ClientException, ServiceException;
    public OSSAsyncTask<UploadPartResult> asyncUploadPart(UploadPartRequest request, final OSSCompletedCallback<UploadPartRequest, UploadPartResult> completedCallback);
}
