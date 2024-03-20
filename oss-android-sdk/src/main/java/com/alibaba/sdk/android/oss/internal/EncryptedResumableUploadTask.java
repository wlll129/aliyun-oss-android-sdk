package com.alibaba.sdk.android.oss.internal;

import android.os.ParcelFileDescriptor;

import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.OSSEncryptionClient;
import com.alibaba.sdk.android.oss.OSSEncryptionImpl;
import com.alibaba.sdk.android.oss.ServiceException;
import com.alibaba.sdk.android.oss.TaskCancelException;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.common.OSSLog;
import com.alibaba.sdk.android.oss.common.utils.BinaryUtil;
import com.alibaba.sdk.android.oss.common.utils.OSSUtils;
import com.alibaba.sdk.android.oss.crypto.MultipartUploadCryptoContext;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadResult;
import com.alibaba.sdk.android.oss.model.ListPartsRequest;
import com.alibaba.sdk.android.oss.model.ListPartsResult;
import com.alibaba.sdk.android.oss.model.PartETag;
import com.alibaba.sdk.android.oss.model.PartSummary;
import com.alibaba.sdk.android.oss.model.ResumableUploadRequest;
import com.alibaba.sdk.android.oss.model.ResumableUploadResult;
import com.alibaba.sdk.android.oss.model.UploadPartRequest;
import com.alibaba.sdk.android.oss.model.UploadPartResult;
import com.alibaba.sdk.android.oss.network.ExecutionContext;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.RandomAccessFile;
import java.util.List;
import java.util.Map;

public class EncryptedResumableUploadTask extends ResumableUploadTask {

    private OSSEncryptionImpl encryptionClient;
    private MultipartUploadCryptoContext cryptoContext;

    public EncryptedResumableUploadTask(ResumableUploadRequest request, OSSCompletedCallback<ResumableUploadRequest, ResumableUploadResult> completedCallback, ExecutionContext context, InternalRequestOperation apiOperation, OSSEncryptionImpl encryptionClient) {
        super(request, completedCallback, context, apiOperation);
        this.encryptionClient = encryptionClient;
    }

    @Override
    protected void initMultipartUploadId() throws IOException, ClientException, ServiceException {
        Map<Integer, Long> recordCrc64 = null;

        if (!OSSUtils.isEmptyString(mRequest.getRecordDirectory())) {
            String fileMd5 = null;
            if (mUploadUri != null) {
                OSSLog.logDebug("[initUploadId] - mUploadFilePath : " + mUploadUri.getPath());
                ParcelFileDescriptor parcelFileDescriptor = mContext.getApplicationContext().getContentResolver().openFileDescriptor(mUploadUri, "r");
                try {
                    fileMd5 = BinaryUtil.calculateMd5Str(parcelFileDescriptor.getFileDescriptor());
                } finally {
                    if (parcelFileDescriptor != null) {
                        parcelFileDescriptor.close();
                    }
                }
            } else {
                OSSLog.logDebug("[initUploadId] - mUploadFilePath : " + mUploadFilePath);
                fileMd5 = BinaryUtil.calculateMd5Str(mUploadFilePath);
            }
            OSSLog.logDebug("[initUploadId] - mRequest.getPartSize() : " + mRequest.getPartSize());
            String recordFileName = BinaryUtil.calculateMd5Str((fileMd5 + mRequest.getBucketName()
                    + mRequest.getObjectKey() + String.valueOf(mRequest.getPartSize()) + (mCheckCRC64 ? "-crc64" : "")).getBytes());
            String recordPath = mRequest.getRecordDirectory() + File.separator + recordFileName;


            mRecordFile = new File(recordPath);
            if (mRecordFile.exists()) {
                BufferedReader br = new BufferedReader(new FileReader(mRecordFile));
                mUploadId = br.readLine();
                br.close();
            }

            OSSLog.logDebug("[initUploadId] - mUploadId : " + mUploadId);

            if (!OSSUtils.isEmptyString(mUploadId)) {
                String cryptoContextFilePath = mRequest.getRecordDirectory() + File.separator + mUploadId + "cryptoContext";
                FileInputStream cryptoContextFileInputStream = new FileInputStream(cryptoContextFilePath);
                ObjectInputStream cryptoContextObjectInputStream = new ObjectInputStream(cryptoContextFileInputStream);
                try {
                    this.cryptoContext = (MultipartUploadCryptoContext) cryptoContextObjectInputStream.readObject();
                } catch (ClassNotFoundException e) {
                    OSSLog.logThrowable2Local(e);
                } finally {
                    if (cryptoContextFileInputStream != null) {
                        cryptoContextFileInputStream.close();
                    }
                }
                if (this.cryptoContext == null) {
                    mRecordFile.delete();
                    mUploadId = null;
                    mRecordFile = null;
                }
            }

            if (!OSSUtils.isEmptyString(mUploadId)) {

                if (mCheckCRC64) {
                    String filePath = mRequest.getRecordDirectory() + File.separator + mUploadId;
                    File crc64Record = new File(filePath);
                    if (crc64Record.exists()) {
                        FileInputStream fs = new FileInputStream(crc64Record);//创建文件字节输出流对象
                        ObjectInputStream ois = new ObjectInputStream(fs);

                        try {
                            recordCrc64 = (Map<Integer, Long>) ois.readObject();
                            crc64Record.delete();
                        } catch (ClassNotFoundException e) {
                            OSSLog.logThrowable2Local(e);
                        } finally {
                            if (ois != null)
                                ois.close();
                            crc64Record.delete();
                        }
                    }
                }


                boolean isTruncated = false;
                int nextPartNumberMarker = 0;


                do{
                    ListPartsRequest listParts = new ListPartsRequest(mRequest.getBucketName(), mRequest.getObjectKey(), mUploadId);
                    if (nextPartNumberMarker > 0){
                        listParts.setPartNumberMarker(nextPartNumberMarker);
                    }

                    OSSAsyncTask<ListPartsResult> task = mApiOperation.listParts(listParts, null);
                    try {
                        ListPartsResult result = task.getResult();
                        isTruncated = result.isTruncated();
                        nextPartNumberMarker = result.getNextPartNumberMarker();
                        List<PartSummary> parts = result.getParts();
                        int partSize = mPartAttr[0];
                        int partTotalNumber = mPartAttr[1];
                        for (int i = 0; i < parts.size(); i++) {
                            PartSummary part = parts.get(i);
                            PartETag partETag = new PartETag(part.getPartNumber(), part.getETag());
                            partETag.setPartSize(part.getSize());

                            if (recordCrc64 != null && recordCrc64.size() > 0) {
                                if (recordCrc64.containsKey(partETag.getPartNumber())) {
                                    partETag.setCRC64(recordCrc64.get(partETag.getPartNumber()));
                                }
                            }
                            OSSLog.logDebug("[initUploadId] -  " + i + " part.getPartNumber() : " + part.getPartNumber());
                            OSSLog.logDebug("[initUploadId] -  " + i + " part.getSize() : " + part.getSize());


                            boolean isTotal = part.getPartNumber() == partTotalNumber;

                            if (isTotal && part.getSize() != mLastPartSize){
                                throw new ClientException("current part size " + part.getSize() + " setting is inconsistent with PartSize : " + partSize + " or lastPartSize : " + mLastPartSize);
                            }

                            if (!isTotal && part.getSize() != partSize){
                                throw new ClientException("current part size " + part.getSize() + " setting is inconsistent with PartSize : " + partSize + " or lastPartSize : " + mLastPartSize);
                            }

                            mPartETags.add(partETag);
                            mUploadedLength += part.getSize();
                            mAlreadyUploadIndex.add(part.getPartNumber());
                        }
                    } catch (ServiceException e) {
                        isTruncated = false;
                        if (e.getStatusCode() == 404) {
                            mUploadId = null;
                        } else {
                            throw e;
                        }
                    } catch (ClientException e) {
                        isTruncated = false;
                        throw e;
                    }
                    task.waitUntilFinished();
                }while (isTruncated);

            }

            if (!mRecordFile.exists() && !mRecordFile.createNewFile()) {
                throw new ClientException("Can't create file at path: " + mRecordFile.getAbsolutePath()
                        + "\nPlease make sure the directory exist!");
            }
        }

        if (OSSUtils.isEmptyString(mUploadId)) {
            cryptoContext = new MultipartUploadCryptoContext();
            cryptoContext.setPartSize(mRequest.getPartSize());
            cryptoContext.setDataSize(mFileLength);

            InitiateMultipartUploadRequest init = new InitiateMultipartUploadRequest(
                    mRequest.getBucketName(), mRequest.getObjectKey(), mRequest.getMetadata());

            InitiateMultipartUploadResult initResult = encryptionClient.initMultipartUpload(init, cryptoContext);

            mUploadId = initResult.getUploadId();

            if (mRecordFile != null) {
                BufferedWriter bw = new BufferedWriter(new FileWriter(mRecordFile));
                bw.write(mUploadId);
                bw.close();

                String cryptoContextFilePath = mRequest.getRecordDirectory() + File.separator + mUploadId + "cryptoContext";
                FileOutputStream fos = new FileOutputStream(cryptoContextFilePath);
                ObjectOutputStream oos = new ObjectOutputStream(fos);

                oos.writeObject(cryptoContext);
            }
        }

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
