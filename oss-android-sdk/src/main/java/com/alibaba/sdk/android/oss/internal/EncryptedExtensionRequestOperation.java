package com.alibaba.sdk.android.oss.internal;

import com.alibaba.sdk.android.oss.OSSEncryptionClient;
import com.alibaba.sdk.android.oss.OSSEncryptionImpl;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.model.ResumableDownloadRequest;
import com.alibaba.sdk.android.oss.model.ResumableDownloadResult;
import com.alibaba.sdk.android.oss.model.ResumableUploadRequest;
import com.alibaba.sdk.android.oss.model.ResumableUploadResult;
import com.alibaba.sdk.android.oss.network.ExecutionContext;

public class EncryptedExtensionRequestOperation extends ExtensionRequestOperation {

    private OSSEncryptionImpl encryptionClient;

    public EncryptedExtensionRequestOperation(InternalRequestOperation apiOperation, OSSEncryptionImpl client) {
        super(apiOperation);
        this.encryptionClient = client;
    }

    public OSSAsyncTask<ResumableUploadResult> resumableUpload(
            ResumableUploadRequest request, OSSCompletedCallback<ResumableUploadRequest
            , ResumableUploadResult> completedCallback) {
        setCRC64(request);
        ExecutionContext<ResumableUploadRequest, ResumableUploadResult> executionContext =
                new ExecutionContext(apiOperation.getInnerClient(), request, apiOperation.getApplicationContext());

        return OSSAsyncTask.wrapRequestTask(executorService.submit(new EncryptedResumableUploadTask(request,
                completedCallback, executionContext, apiOperation, encryptionClient)), executionContext);
    }

    @Override
    public OSSAsyncTask<ResumableDownloadResult> resumableDownload(ResumableDownloadRequest request, OSSCompletedCallback<ResumableDownloadRequest, ResumableDownloadResult> completedCallback) {
        ExecutionContext<ResumableDownloadRequest, ResumableDownloadResult> executionContext =
                new ExecutionContext(apiOperation.getInnerClient(), request, apiOperation.getApplicationContext());

        return OSSAsyncTask.wrapRequestTask(executorService.submit(new EncryptedResumableDownloadTask(apiOperation, request,
                completedCallback, executionContext, encryptionClient)), executionContext);
    }
}
