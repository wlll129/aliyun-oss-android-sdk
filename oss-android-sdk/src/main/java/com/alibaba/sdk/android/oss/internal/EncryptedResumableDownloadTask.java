package com.alibaba.sdk.android.oss.internal;

import com.alibaba.sdk.android.oss.OSSEncryption;
import com.alibaba.sdk.android.oss.OSSEncryptionClient;
import com.alibaba.sdk.android.oss.OSSEncryptionImpl;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.common.OSSLog;
import com.alibaba.sdk.android.oss.common.utils.CRC64;
import com.alibaba.sdk.android.oss.crypto.AdjustedRangeInputStream;
import com.alibaba.sdk.android.oss.crypto.CipherInputStream;
import com.alibaba.sdk.android.oss.model.GetObjectRequest;
import com.alibaba.sdk.android.oss.model.GetObjectResult;
import com.alibaba.sdk.android.oss.model.OSSRequest;
import com.alibaba.sdk.android.oss.model.Range;
import com.alibaba.sdk.android.oss.model.ResumableDownloadRequest;
import com.alibaba.sdk.android.oss.network.ExecutionContext;

import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.util.Map;
import java.util.zip.CheckedInputStream;

public class EncryptedResumableDownloadTask extends ResumableDownloadTask {

    private OSSEncryptionImpl client;

    EncryptedResumableDownloadTask(InternalRequestOperation operation, ResumableDownloadRequest request, OSSCompletedCallback completedCallback, ExecutionContext context, OSSEncryptionImpl client) {
        super(operation, request, completedCallback, context);
        this.client = client;
    }

    @Override
    protected void downloadPart(DownloadFileResult downloadResult, DownloadPart part) {
        RandomAccessFile output = null;
        InputStream content = null;
        try {

            if (mContext.getCancellationHandler().isCancelled()) {
                mPoolExecutor.getQueue().clear();
            }

            downloadPartSize += 1;

            output = new RandomAccessFile(mRequest.getTempFilePath(), "rw");
            output.seek(part.fileStart);

            Map<String, String> requestHeader = mRequest.getRequestHeader();

            long end = part.end;
            if (end == -1) {
                end = part.start + part.length - 1;
            }
            GetObjectRequest request = new GetObjectRequest(mRequest.getBucketName(), mRequest.getObjectKey());
            request.setRange(new Range(part.start, end));
            request.setRequestHeaders(requestHeader);
            OSSLog.logInfo(request.getRange().toString());

            GetObjectResult result =  client.getObject(request);

            content = result.getObjectContent();

            byte[] buffer = new byte[(int)(part.length)];
            long readLength = 0;

            while ((readLength = content.read(buffer)) != -1) {
                output.write(buffer, 0, (int) readLength);
            }

            synchronized (mLock) {

                DownloadPartResult partResult = new DownloadPartResult();
                partResult.partNumber = part.partNumber;
                partResult.requestId = result.getRequestId();
                partResult.length = result.getContentLength();
                if (mRequest.getCRC64() == OSSRequest.CRC64Config.YES) {
                    Long clientCRC = getCRC64(content);
                    partResult.clientCRC = clientCRC;

                    part.crc = clientCRC;
                }
                downloadResult.partResults.add(partResult);
                if (downloadResult.metadata == null) {
                    downloadResult.metadata = result.getMetadata();
                }

                completedPartSize += 1;

                if (mContext.getCancellationHandler().isCancelled()) {
                    // Cancel after the last task is completed
                    if (downloadPartSize == completedPartSize - mPartExceptionCount) {
                        checkCancel();
                    }
                } else {
                    // After all tasks are completed, wake up the thread where the doMultipartDownload method is located
                    if (mCheckPoint.parts.size() == (completedPartSize - mPartExceptionCount)) {
                        notifyMultipartThread();
                    }
                    mCheckPoint.update(part.partNumber, true);
                    if (mRequest.getEnableCheckPoint()) {
                        mCheckPoint.dump(checkpointPath);
                    }
                    Range range = correctRange(mRequest.getRange(), mCheckPoint.fileStat.fileLength);
                    if (mProgressCallback != null) {
                        mProgressCallback.onProgress(mRequest, mCheckPoint.downloadLength, range.getEnd() - range.getBegin());
                    }
                }
            }
        } catch (Exception e) {
            processException(e);
        } finally {
            try {
                if (output != null) {
                    output.close();
                }
                if (content != null) {
                    content.close();
                }
            } catch (IOException e) {
                OSSLog.logThrowable2Local(e);
            }
        }
    }

    private Long getCRC64(InputStream inputStream) {
        if (inputStream instanceof AdjustedRangeInputStream) {
            InputStream cipherInputStream = ((AdjustedRangeInputStream)inputStream).getWrappedInputStream();
            if (cipherInputStream instanceof CipherInputStream) {
                InputStream chechCRCInputStream = ((CipherInputStream) cipherInputStream).getDelegateStream();
                if (chechCRCInputStream instanceof CheckedInputStream) {
                    return ((CheckedInputStream) chechCRCInputStream).getChecksum().getValue();
                }
            }
        }
        return null;
    }
}
