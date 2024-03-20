package com.alibaba.sdk.android.oss.internal;

import android.content.Context;

import com.alibaba.sdk.android.oss.ClientConfiguration;
import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.ServiceException;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.common.HttpMethod;
import com.alibaba.sdk.android.oss.common.OSSLog;
import com.alibaba.sdk.android.oss.common.auth.OSSCredentialProvider;
import com.alibaba.sdk.android.oss.common.utils.OSSUtils;
import com.alibaba.sdk.android.oss.model.EncryptedPutObjectRequest;
import com.alibaba.sdk.android.oss.model.PutObjectRequest;
import com.alibaba.sdk.android.oss.model.PutObjectResult;
import com.alibaba.sdk.android.oss.network.ExecutionContext;
import com.alibaba.sdk.android.oss.network.OSSRequestTask;

import java.net.URI;
import java.util.concurrent.Callable;

public class EncryptedInternalRequestOperation extends InternalRequestOperation {

    public EncryptedInternalRequestOperation(Context context, URI endpoint, OSSCredentialProvider credentialProvider, ClientConfiguration conf) {
        super(context, endpoint, credentialProvider, conf);
    }

    public EncryptedInternalRequestOperation(Context context, OSSCredentialProvider credentialProvider, ClientConfiguration conf) {
        super(context, credentialProvider, conf);
    }

    @Override
    public OSSAsyncTask<PutObjectResult> putObject(PutObjectRequest request, final OSSCompletedCallback<PutObjectRequest, PutObjectResult> completedCallback) {
        OSSLog.logDebug(" Internal putObject Start ");
        RequestMessage requestMessage = new RequestMessage();
        requestMessage.setIsAuthorizationRequired(request.isAuthorizationRequired());
        requestMessage.setEndpoint(getEndpoint());
        requestMessage.setMethod(HttpMethod.PUT);
        requestMessage.setBucketName(request.getBucketName());
        requestMessage.setObjectKey(request.getObjectKey());

        if (request instanceof EncryptedPutObjectRequest) {
            requestMessage.setContent(((EncryptedPutObjectRequest)request).getContent());
            requestMessage.setContentLength(((EncryptedPutObjectRequest)request).getContentLength());
        }

        if (request.getCallbackParam() != null) {
            requestMessage.getHeaders().put("x-oss-callback", OSSUtils.populateMapToBase64JsonString(request.getCallbackParam()));
        }
        if (request.getCallbackVars() != null) {
            requestMessage.getHeaders().put("x-oss-callback-var", OSSUtils.populateMapToBase64JsonString(request.getCallbackVars()));
        }
        OSSLog.logDebug(" populateRequestMetadata ");
        OSSUtils.populateRequestMetadata(requestMessage.getHeaders(), request.getMetadata());
        OSSLog.logDebug(" canonicalizeRequestMessage ");
        canonicalizeRequestMessage(requestMessage, request);
        OSSLog.logDebug(" ExecutionContext ");
        ExecutionContext<PutObjectRequest, PutObjectResult> executionContext = new ExecutionContext(getInnerClient(), request, getApplicationContext());
        if (completedCallback != null) {
            executionContext.setCompletedCallback(new OSSCompletedCallback<PutObjectRequest, PutObjectResult>() {
                @Override
                public void onSuccess(PutObjectRequest request, PutObjectResult result) {
                    checkCRC64(request, result, completedCallback);
                }

                @Override
                public void onFailure(PutObjectRequest request, ClientException clientException, ServiceException serviceException) {
                    completedCallback.onFailure(request, clientException, serviceException);
                }
            });
        }

        if (request.getRetryCallback() != null) {
            executionContext.setRetryCallback(request.getRetryCallback());
        }

        executionContext.setProgressCallback(request.getProgressCallback());
        ResponseParser<PutObjectResult> parser = new ResponseParsers.PutObjectResponseParser();

        Callable<PutObjectResult> callable = new OSSRequestTask<PutObjectResult>(requestMessage, parser, executionContext, getMaxRetryCount());
        OSSLog.logDebug(" call OSSRequestTask ");
        return OSSAsyncTask.wrapRequestTask(getExecutorService().submit(callable), executionContext);
    }

}
