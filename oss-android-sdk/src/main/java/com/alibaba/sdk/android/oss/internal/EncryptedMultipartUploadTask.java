package com.alibaba.sdk.android.oss.internal;

import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.OSSEncryptionClient;
import com.alibaba.sdk.android.oss.ServiceException;
import com.alibaba.sdk.android.oss.TaskCancelException;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.common.OSSLog;
import com.alibaba.sdk.android.oss.common.utils.BinaryUtil;
import com.alibaba.sdk.android.oss.crypto.MultipartUploadCryptoContext;
import com.alibaba.sdk.android.oss.model.CompleteMultipartUploadResult;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadResult;
import com.alibaba.sdk.android.oss.model.MultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.PartETag;
import com.alibaba.sdk.android.oss.model.UploadPartRequest;
import com.alibaba.sdk.android.oss.model.UploadPartResult;
import com.alibaba.sdk.android.oss.network.ExecutionContext;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;

public class EncryptedMultipartUploadTask extends MultipartUploadTask {

    private OSSEncryptionClient encryptionClient;
    private MultipartUploadCryptoContext cryptoContext;

    public EncryptedMultipartUploadTask(InternalRequestOperation operation, MultipartUploadRequest request, OSSCompletedCallback<MultipartUploadRequest, CompleteMultipartUploadResult> completedCallback, ExecutionContext context, OSSEncryptionClient encryptionClient) {
        super(operation, request, completedCallback, context);
        this.encryptionClient = encryptionClient;
    }

    @Override
    protected void initMultipartUploadId() throws ClientException, ServiceException {

        cryptoContext = new MultipartUploadCryptoContext();
        cryptoContext.setPartSize(mRequest.getPartSize());
        cryptoContext.setDataSize(mFileLength);

        InitiateMultipartUploadRequest init = new InitiateMultipartUploadRequest(
                mRequest.getBucketName(), mRequest.getObjectKey(), mRequest.getMetadata());

        InitiateMultipartUploadResult initResult = encryptionClient.initMultipartUpload(init, cryptoContext);

        mUploadId = initResult.getUploadId();
        mRequest.setUploadId(mUploadId);
    }

    @Override
    protected void uploadPart(int readIndex, int byteCount, int partNumber) {
        RandomAccessFile raf = null;
        InputStream inputStream = null;
        BufferedInputStream bufferedInputStream = null;
        try {

            if (mContext.getCancellationHandler().isCancelled()) {
                mPoolExecutor.getQueue().clear();
                return;
            }

            synchronized (mLock) {
                mRunPartTaskCount++;
            }

            preUploadPart(readIndex, byteCount, partNumber);

            byte[] partContent = new byte[byteCount];
            long skip = readIndex * mRequest.getPartSize();
            if (mUploadUri != null) {
                inputStream = mContext.getApplicationContext().getContentResolver().openInputStream(mUploadUri);
                bufferedInputStream = new BufferedInputStream(inputStream);
                bufferedInputStream.skip(skip);
                bufferedInputStream.read(partContent, 0, byteCount);
            } else {
                raf = new RandomAccessFile(mUploadFile, "r");

                raf.seek(skip);
                raf.readFully(partContent, 0, byteCount);
            }

            UploadPartRequest uploadPart = new UploadPartRequest(
                    mRequest.getBucketName(), mRequest.getObjectKey(), mUploadId, readIndex + 1);
            uploadPart.setPartContent(partContent);
            uploadPart.setMd5Digest(BinaryUtil.calculateBase64Md5(partContent));
            uploadPart.setCRC64(mRequest.getCRC64());
            UploadPartResult uploadPartResult = encryptionClient.uploadPart(uploadPart, cryptoContext);
            //check isComplete
            synchronized (mLock) {
                PartETag partETag = new PartETag(uploadPart.getPartNumber(), uploadPartResult.getETag());
                partETag.setPartSize(byteCount);
                if (mCheckCRC64) {
                    partETag.setCRC64(uploadPartResult.getClientCRC());
                }

                mPartETags.add(partETag);
                mUploadedLength += byteCount;

                uploadPartFinish(partETag);

                if (mContext.getCancellationHandler().isCancelled()) {
                    if (mPartETags.size() == (mRunPartTaskCount - mPartExceptionCount)) {
                        TaskCancelException e = new TaskCancelException("multipart cancel");

                        throw new ClientException(e.getMessage(), e, true);
                    }
                } else {
                    if (mPartETags.size() == (partNumber - mPartExceptionCount)) {
                        notifyMultipartThread();
                    }
                    onProgressCallback(mRequest, mUploadedLength, mFileLength);
                }

            }

        } catch (Exception e) {
            processException(e);
        } finally {
            try {
                if (raf != null)
                    raf.close();
                if (bufferedInputStream != null)
                    bufferedInputStream.close();
                if (inputStream != null)
                    inputStream.close();
            } catch (IOException e) {
                OSSLog.logThrowable2Local(e);
            }
        }
    }
}
