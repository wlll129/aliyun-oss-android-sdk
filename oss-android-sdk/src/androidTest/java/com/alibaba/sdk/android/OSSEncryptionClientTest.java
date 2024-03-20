package com.alibaba.sdk.android;

import android.net.Uri;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.SdkSuppress;
import android.util.Log;

import com.alibaba.sdk.android.oss.ClientConfiguration;
import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.OSSEncryptionClient;
import com.alibaba.sdk.android.oss.ServiceException;
import com.alibaba.sdk.android.oss.callback.OSSProgressCallback;
import com.alibaba.sdk.android.oss.common.utils.BinaryUtil;
import com.alibaba.sdk.android.oss.common.utils.CRC64;
import com.alibaba.sdk.android.oss.common.utils.IOUtils;
import com.alibaba.sdk.android.oss.crypto.CryptoConfiguration;
import com.alibaba.sdk.android.oss.crypto.EncryptionMaterials;
import com.alibaba.sdk.android.oss.crypto.MultipartUploadCryptoContext;
import com.alibaba.sdk.android.oss.crypto.SimpleRSAEncryptionMaterials;
import com.alibaba.sdk.android.oss.internal.OSSAsyncTask;
import com.alibaba.sdk.android.oss.model.CompleteMultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.CompleteMultipartUploadResult;
import com.alibaba.sdk.android.oss.model.GetObjectRequest;
import com.alibaba.sdk.android.oss.model.GetObjectResult;
import com.alibaba.sdk.android.oss.model.HeadObjectRequest;
import com.alibaba.sdk.android.oss.model.HeadObjectResult;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadResult;
import com.alibaba.sdk.android.oss.model.MultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.OSSRequest;
import com.alibaba.sdk.android.oss.model.ObjectMetadata;
import com.alibaba.sdk.android.oss.model.PartETag;
import com.alibaba.sdk.android.oss.model.PutObjectRequest;
import com.alibaba.sdk.android.oss.model.Range;
import com.alibaba.sdk.android.oss.model.ResumableDownloadRequest;
import com.alibaba.sdk.android.oss.model.ResumableDownloadResult;
import com.alibaba.sdk.android.oss.model.ResumableUploadRequest;
import com.alibaba.sdk.android.oss.model.UploadPartRequest;
import com.alibaba.sdk.android.oss.model.UploadPartResult;

import org.junit.Test;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.alibaba.sdk.android.OSSTestConfig.FILE_DIR;
import static com.alibaba.sdk.android.oss.crypto.CryptoHeaders.CRYPTO_UNENCRYPTION_CONTENT_MD5;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class OSSEncryptionClientTest extends BaseTestCase {

    private OSSEncryptionClient encryptionClient;

    private final String PUBLIC_KEY_PEM_XC509 =
            "-----BEGIN PUBLIC KEY-----\n"
                    + "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIUc0RE+OF4qvJkFp/sBR4iiPy\n"
                    + "5czlKdHoOKOjhvh93aGpipoMb05+t07XSOBDJUzKGhqqVQJZEQahKXJUU0h3mxYy\n"
                    + "xRQMhhWWWdH1LH4s/GAjf4h5l+6tKxS6mnZGH4IlbJz1pvbPiZjzD6BEWtGBMAxZ\n" + "IjqPgSRjJpB6fBIrHQIDAQAB\n"
                    + "-----END PUBLIC KEY-----";

    private static String PRIVATE_KEY_PEM_PKCS8 =
            "-----BEGIN PRIVATE KEY-----\n"
                    + "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMhRzRET44Xiq8mQ\n"
                    + "Wn+wFHiKI/LlzOUp0eg4o6OG+H3doamKmgxvTn63TtdI4EMlTMoaGqpVAlkRBqEp\n"
                    + "clRTSHebFjLFFAyGFZZZ0fUsfiz8YCN/iHmX7q0rFLqadkYfgiVsnPWm9s+JmPMP\n"
                    + "oERa0YEwDFkiOo+BJGMmkHp8EisdAgMBAAECgYAbuSZ2TJhaeSppNO8xaL8Mh6G+\n"
                    + "Bgu7U3RXfS84fH97e+bZvfLf8a+dXeUtakqPQGRGPCKgnC89AFw4hbHq9bO7iygc\n"
                    + "0j57UVMmAURN9azX4cA+BH0am1sMkZ1UdziLzkkH6cq9u4Sab+SrTGZ1Dc55JWpm\n"
                    + "rJ+WYZOdwIxQArlYAQJBAOkHCzd4NrvDhKtnKiYwyK/RRboZhZZfGe9JXMrYDnkB\n"
                    + "CJKh6NTZE+FnosnO6+vYx7P2XuY6/KIm+91xo7pRrB0CQQDcEUzbPzabdD15g9J6\n"
                    + "AHaScIC4pONlmYMu3sht3/PUqB0qve2nNG1Y2XGpLSX1uw3v0h9LAbDBsUWGJBKt\n"
                    + "ZEsBAkAmz2CD3YaoIPkgnu77K1bRSXZmd0ezcqVcIAjPU8qdRpnJ6iNgB8Ny4BLR\n"
                    + "r5/FSPaBt3+4soxO6VU7XWjaaC3VAkEAkFtQ3Sk0OvkfMkzEjn8rSJg/999Bw23V\n"
                    + "3bMKKvkTS1YT++umr132tKe+pUkWc4EGfWCKYntzZTtR7dJP5im6AQJBAMZIDGwt\n"
                    + "pIYUt9sE4rMzuym/dy/Nru9gGSx9HrFPopFpRGHrJoaaQryB+auQUy1ZDQILd815\n" + "x7BQ0ulJy4q6cKE=\n"
                    + "-----END PRIVATE KEY-----";

    @Override
    void initTestData() throws Exception {
        OSSTestConfig.initLocalFile();
        OSSTestConfig.initDemoFile("guihua.zip");
        initEncryptionOSS();
    }

    void initEncryptionOSS() throws ClientException {
        final RSAPublicKey publicKey = SimpleRSAEncryptionMaterials.getPublicKeyFromPemX509(PUBLIC_KEY_PEM_XC509);
        final RSAPrivateKey privateKey = SimpleRSAEncryptionMaterials.getPrivateKeyFromPemPKCS8(PRIVATE_KEY_PEM_PKCS8);
        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        EncryptionMaterials encryptionMaterials = new SimpleRSAEncryptionMaterials(keyPair);

        ClientConfiguration clientConfiguration = new ClientConfiguration();
        CryptoConfiguration cryptoConfiguration = new CryptoConfiguration();

        encryptionClient = new OSSEncryptionClient(InstrumentationRegistry.getTargetContext(), OSSTestConfig.ENDPOINT, OSSTestConfig.credentialProvider, clientConfiguration, encryptionMaterials, cryptoConfiguration);
    }

    @Test
    public void textSyncPutAndGetObjectWithFilePath() throws ClientException, ServiceException, IOException {
        final String objectKey = "file1m.jpg";
        PutObjectRequest put = new PutObjectRequest(mBucketName, objectKey,
                FILE_DIR + "file1m");
        encryptionClient.putObject(put);

        GetObjectRequest get = new GetObjectRequest(mBucketName, objectKey);
        GetObjectResult result = encryptionClient.getObject(get);
        byte[] content = IOUtils.readStreamAsBytesArray(result.getObjectContent());

        assertEquals(BinaryUtil.calculateBase64Md5(content), BinaryUtil.calculateBase64Md5(FILE_DIR + "file1m"));
    }

    @Test
    public void textAsyncPutAndGetObjectWithFilePath() throws IOException {
        OSSTestConfig.TestPutCallback putCallback = new OSSTestConfig.TestPutCallback();
        OSSTestConfig.TestGetCallback getCallback = new OSSTestConfig.TestGetCallback();

        final String objectKey = "file1m.jpg";
        PutObjectRequest put = new PutObjectRequest(mBucketName, objectKey,
                FILE_DIR + "file1m");
        OSSAsyncTask putTask = encryptionClient.asyncPutObject(put, putCallback);
        putTask.waitUntilFinished();
        assertEquals(putCallback.result.getStatusCode(), 200);

        GetObjectRequest get = new GetObjectRequest(mBucketName, objectKey);
        OSSAsyncTask getTask = encryptionClient.asyncGetObject(get, getCallback);
        getTask.waitUntilFinished();

        assertEquals(getCallback.result.getStatusCode(), 200);
        byte[] content = IOUtils.readStreamAsBytesArray(getCallback.result.getObjectContent());

        assertEquals(BinaryUtil.calculateBase64Md5(content), BinaryUtil.calculateBase64Md5(FILE_DIR + "file1m"));
    }

    @Test
    @SdkSuppress(minSdkVersion = 29)
    public void textPutAndGetObjectWithFileUri() throws IOException {
        OSSTestConfig.TestPutCallback putCallback = new OSSTestConfig.TestPutCallback();
        OSSTestConfig.TestGetCallback getCallback = new OSSTestConfig.TestGetCallback();

        final String objectKey = "file1m.jpg";
        Uri uri = OSSTestConfig.queryUri("file1m");

        PutObjectRequest put = new PutObjectRequest(mBucketName, objectKey, uri);
        OSSAsyncTask putTask = encryptionClient.asyncPutObject(put, putCallback);
        putTask.waitUntilFinished();
        assertEquals(putCallback.result.getStatusCode(), 200);

        GetObjectRequest get = new GetObjectRequest(mBucketName, objectKey);
        OSSAsyncTask getTask = encryptionClient.asyncGetObject(get, getCallback);
        getTask.waitUntilFinished();

        assertEquals(getCallback.result.getStatusCode(), 200);
        byte[] content = IOUtils.readStreamAsBytesArray(getCallback.result.getObjectContent());

        FileDescriptor fileDescriptor = InstrumentationRegistry.getContext().getContentResolver().openFileDescriptor(uri, "r").getFileDescriptor();

        assertEquals(BinaryUtil.calculateBase64Md5(content), BinaryUtil.calculateBase64Md5(fileDescriptor));
    }

    @Test
    public void textPutAndGetObjectWithData() throws IOException {
        OSSTestConfig.TestPutCallback putCallback = new OSSTestConfig.TestPutCallback();
        OSSTestConfig.TestGetCallback getCallback = new OSSTestConfig.TestGetCallback();

        final String originContent = "qwertyuuihonkffttdctgvbkhiijojilkmkeowirnskdnsiwi93729741084084875dfdf212fa";

        final String objectKey = "file1m.jpg";
        PutObjectRequest put = new PutObjectRequest(mBucketName, objectKey, originContent.getBytes());
        OSSAsyncTask putTask = encryptionClient.asyncPutObject(put, putCallback);
        putTask.waitUntilFinished();
        assertEquals(putCallback.result.getStatusCode(), 200);

        GetObjectRequest get = new GetObjectRequest(mBucketName, objectKey);
        OSSAsyncTask getTask = encryptionClient.asyncGetObject(get, getCallback);
        getTask.waitUntilFinished();

        assertEquals(getCallback.result.getStatusCode(), 200);
        byte[] content = IOUtils.readStreamAsBytesArray(getCallback.result.getObjectContent());

        assertEquals(BinaryUtil.calculateBase64Md5(content), BinaryUtil.calculateBase64Md5(originContent.getBytes()));
    }

    @Test
    public void textPutAndGetObjectWithContentMD5() throws IOException {
        OSSTestConfig.TestPutCallback putCallback = new OSSTestConfig.TestPutCallback();
        OSSTestConfig.TestGetCallback getCallback = new OSSTestConfig.TestGetCallback();

        final String objectKey = "file1m.jpg";
        PutObjectRequest put = new PutObjectRequest(mBucketName, objectKey,
                FILE_DIR + "file1m");
        String contentMD5 = BinaryUtil.calculateBase64Md5(FILE_DIR + "file1m");
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentMD5(contentMD5);
        put.setMetadata(metadata);
        OSSAsyncTask putTask = encryptionClient.asyncPutObject(put, putCallback);
        putTask.waitUntilFinished();
        assertEquals(putCallback.result.getStatusCode(), 200);

        GetObjectRequest get = new GetObjectRequest(mBucketName, objectKey);
        OSSAsyncTask getTask = encryptionClient.asyncGetObject(get, getCallback);
        getTask.waitUntilFinished();

        assertEquals(getCallback.result.getStatusCode(), 200);
        String unEncryptionContentMD5 = getCallback.result.getMetadata().getUserMetadata().get(CRYPTO_UNENCRYPTION_CONTENT_MD5);
        assertEquals(unEncryptionContentMD5, contentMD5);
        byte[] content = IOUtils.readStreamAsBytesArray(getCallback.result.getObjectContent());

        assertEquals(BinaryUtil.calculateBase64Md5(content), BinaryUtil.calculateBase64Md5(FILE_DIR + "file1m"));
    }

    @Test
    public void textAsyncGetObjectWithRange() throws IOException {
        OSSTestConfig.TestPutCallback putCallback = new OSSTestConfig.TestPutCallback();
        OSSTestConfig.TestGetCallback getCallback = new OSSTestConfig.TestGetCallback();

        final String objectKey = "file1m.jpg";
        PutObjectRequest put = new PutObjectRequest(mBucketName, objectKey,
                FILE_DIR + "file1m");
        OSSAsyncTask putTask = encryptionClient.asyncPutObject(put, putCallback);
        putTask.waitUntilFinished();
        assertEquals(putCallback.result.getStatusCode(), 200);

        GetObjectRequest get = new GetObjectRequest(mBucketName, objectKey);
        get.setCRC64(OSSRequest.CRC64Config.YES);
        get.setRange(new Range(100, 199));
        OSSAsyncTask getTask = encryptionClient.asyncGetObject(get, getCallback);
        getTask.waitUntilFinished();

        assertTrue(getCallback.result.getStatusCode() < 300);
        byte[] content = IOUtils.readStreamAsBytesArray(getCallback.result.getObjectContent());

        FileInputStream fileInputStream = new FileInputStream(FILE_DIR + "file1m");
        byte[] originContent = IOUtils.readStreamAsBytesArray(fileInputStream);
        originContent = Arrays.copyOfRange(originContent, 100, 200);

        assertEquals(BinaryUtil.calculateBase64Md5(content), BinaryUtil.calculateBase64Md5(originContent));
    }

    @Test
    public void testMultipartUpload() throws IOException {
        OSSTestConfig.TestMultipartUploadCallback multipartUploadCallback = new OSSTestConfig.TestMultipartUploadCallback();
        OSSTestConfig.TestGetCallback getCallback = new OSSTestConfig.TestGetCallback();

        final String objectKey = "file10m.jpg";
        MultipartUploadRequest put = new MultipartUploadRequest(mBucketName, objectKey,
                FILE_DIR + "file10m");
        OSSAsyncTask putTask = encryptionClient.asyncMultipartUpload(put, multipartUploadCallback);
        putTask.waitUntilFinished();
        assertEquals(multipartUploadCallback.result.getStatusCode(), 200);

        GetObjectRequest get = new GetObjectRequest(mBucketName, objectKey);
        OSSAsyncTask getTask = encryptionClient.asyncGetObject(get, getCallback);
        getTask.waitUntilFinished();

//        assertEquals(getCallback.result.getStatusCode(), 200);
        byte[] content = IOUtils.readStreamAsBytesArray(getCallback.result.getObjectContent());

        FileInputStream fileInputStream = new FileInputStream(FILE_DIR + "file10m");
        byte[] originContent = IOUtils.readStreamAsBytesArray(fileInputStream);

        assertEquals(BinaryUtil.calculateBase64Md5(content), BinaryUtil.calculateBase64Md5(originContent));
    }

    @Test
    public void testResumeUpload() throws IOException {
        OSSTestConfig.TestResumableUploadCallback resumableUploadCallback = new OSSTestConfig.TestResumableUploadCallback();
        OSSTestConfig.TestGetCallback getCallback = new OSSTestConfig.TestGetCallback();

        final String objectKey = "file10m.jpg";
        ResumableUploadRequest put = new ResumableUploadRequest(mBucketName, objectKey,
                FILE_DIR + "file10m");
        OSSAsyncTask putTask = encryptionClient.asyncResumableUpload(put, resumableUploadCallback);
        putTask.waitUntilFinished();
        assertEquals(resumableUploadCallback.result.getStatusCode(), 200);

        GetObjectRequest get = new GetObjectRequest(mBucketName, objectKey);
        OSSAsyncTask getTask = encryptionClient.asyncGetObject(get, getCallback);
        getTask.waitUntilFinished();

//        assertEquals(getCallback.result.getStatusCode(), 200);
        byte[] content = IOUtils.readStreamAsBytesArray(getCallback.result.getObjectContent());

        FileInputStream fileInputStream = new FileInputStream(FILE_DIR + "file10m");
        byte[] originContent = IOUtils.readStreamAsBytesArray(fileInputStream);

        assertEquals(BinaryUtil.calculateBase64Md5(content), BinaryUtil.calculateBase64Md5(originContent));
    }

    @Test
    public void testResumableUploadWithCancel() throws IOException {
        OSSTestConfig.TestResumableUploadCallback resumableUploadCallback = new OSSTestConfig.TestResumableUploadCallback();
        OSSTestConfig.TestGetCallback getCallback = new OSSTestConfig.TestGetCallback();

        String recordPath = FILE_DIR + "OSS";
        final String objectKey = "file10m.jpg";
        ResumableUploadRequest put = new ResumableUploadRequest(mBucketName, objectKey,
                FILE_DIR + "file10m", recordPath);
        put.setPartSize(100 * 1024);
        final AtomicBoolean needCancelled = new AtomicBoolean(false);
        put.setProgressCallback(new OSSProgressCallback() {
            @Override
            public void onProgress(Object request, long currentSize, long totalSize) {
                needCancelled.set(currentSize > totalSize/3);
            }
        });
        OSSAsyncTask putTask = encryptionClient.asyncResumableUpload(put, resumableUploadCallback);
        while (!needCancelled.get()) {}
        putTask.cancel();

        put.setProgressCallback(new OSSProgressCallback() {
            @Override
            public void onProgress(Object request, long currentSize, long totalSize) {
                assertTrue(currentSize > totalSize / 3);
            }
        });
        putTask = encryptionClient.asyncResumableUpload(put, resumableUploadCallback);
        putTask.waitUntilFinished();
        assertEquals(resumableUploadCallback.result.getStatusCode(), 200);

        GetObjectRequest get = new GetObjectRequest(mBucketName, objectKey);
        OSSAsyncTask getTask = encryptionClient.asyncGetObject(get, getCallback);
        getTask.waitUntilFinished();

//        assertEquals(getCallback.result.getStatusCode(), 200);
        byte[] content = IOUtils.readStreamAsBytesArray(getCallback.result.getObjectContent());

        FileInputStream fileInputStream = new FileInputStream(FILE_DIR + "file10m");
        byte[] originContent = IOUtils.readStreamAsBytesArray(fileInputStream);

        assertEquals(BinaryUtil.calculateBase64Md5(content), BinaryUtil.calculateBase64Md5(originContent));
    }

    @Test
    public void testSyncUploadPart() throws IOException, ClientException, ServiceException {

        OSSTestConfig.TestGetCallback getCallback = new OSSTestConfig.TestGetCallback();

        final long partSize = 100 * 1024L; // 100;
        final String objectKey = "file10m";
        final String filePath = FILE_DIR + "file10m";
        File file = new File(filePath);

        MultipartUploadCryptoContext context = new MultipartUploadCryptoContext();
        context.setPartSize(partSize);
        context.setDataSize(file.length());

        InitiateMultipartUploadRequest initiateMultipartUploadRequest = new InitiateMultipartUploadRequest(mBucketName, objectKey);
        InitiateMultipartUploadResult initiateMultipartUploadResult = encryptionClient.initMultipartUpload(initiateMultipartUploadRequest, context);

        assertEquals(initiateMultipartUploadResult.getStatusCode(), 200);
        assertEquals(context.getUploadId(), initiateMultipartUploadResult.getUploadId());

        int partCount = (int) (file.length() / partSize);
        List<PartETag> partETags = new ArrayList<PartETag>();
        partCount += (file.length() % partSize) > 0 ? 1 : 0;

        RandomAccessFile randomAccessFile = new RandomAccessFile(filePath, "r");
        for (int i = 0; i < partCount; i++) {
            randomAccessFile.seek(i * partSize);
            byte[] partContent = new byte[(int) partSize];
            randomAccessFile.read(partContent, 0, (int) partSize);

            UploadPartRequest uploadPartRequest = new UploadPartRequest(mBucketName, objectKey, context.getUploadId(), i + 1);
            uploadPartRequest.setPartContent(partContent);
            uploadPartRequest.setMd5Digest(BinaryUtil.calculateBase64Md5(partContent));

            UploadPartResult uploadPartResult = encryptionClient.uploadPart(uploadPartRequest, context);
            assertEquals(uploadPartResult.getStatusCode(), 200);
            PartETag partETag = new PartETag(i + 1, uploadPartResult.getETag());
            partETags.add(partETag);
        }

        CompleteMultipartUploadRequest completeMultipartUploadRequest = new CompleteMultipartUploadRequest(mBucketName, objectKey, context.getUploadId(), partETags);
        CompleteMultipartUploadResult completeMultipartUploadResult = encryptionClient.completeMultipartUpload(completeMultipartUploadRequest);
        assertEquals(completeMultipartUploadResult.getStatusCode(), 200);

        GetObjectRequest get = new GetObjectRequest(mBucketName, objectKey);
        OSSAsyncTask getTask = encryptionClient.asyncGetObject(get, getCallback);
        getTask.waitUntilFinished();

        byte[] content = IOUtils.readStreamAsBytesArray(getCallback.result.getObjectContent());

        FileInputStream fileInputStream = new FileInputStream(filePath);
        byte[] originContent = IOUtils.readStreamAsBytesArray(fileInputStream);

        assertEquals(BinaryUtil.calculateBase64Md5(content), BinaryUtil.calculateBase64Md5(originContent));
    }

    @Test
    public void testAsyncUploadPart() throws IOException, ClientException, ServiceException {

        OSSTestConfig.TestInitiateMultipartCallback initiateMultipartCallback = new OSSTestConfig.TestInitiateMultipartCallback();
        OSSTestConfig.TestGetCallback getCallback = new OSSTestConfig.TestGetCallback();

        final long partSize = 100 * 1024L; // 100;
        final String objectKey = "file10m";
        final String filePath = FILE_DIR + "file10m";
        File file = new File(filePath);

        MultipartUploadCryptoContext context = new MultipartUploadCryptoContext();
        context.setPartSize(partSize);
        context.setDataSize(file.length());

        InitiateMultipartUploadRequest initiateMultipartUploadRequest = new InitiateMultipartUploadRequest(mBucketName, objectKey);
        OSSAsyncTask initTask = encryptionClient.asyncInitMultipartUpload(initiateMultipartUploadRequest, context, initiateMultipartCallback);
        initTask.waitUntilFinished();

        assertEquals(initiateMultipartCallback.result.getStatusCode(), 200);
        assertEquals(context.getUploadId(), initiateMultipartCallback.result.getUploadId());

        int partCount = (int) (file.length() / partSize);
        List<PartETag> partETags = new ArrayList<PartETag>();
        partCount += (file.length() % partSize) > 0 ? 1 : 0;

        RandomAccessFile randomAccessFile = new RandomAccessFile(filePath, "r");
        for (int i = 0; i < partCount; i++) {
            OSSTestConfig.TestUploadPartsCallback uploadPartsCallback = new OSSTestConfig.TestUploadPartsCallback();

            randomAccessFile.seek(i * partSize);
            byte[] partContent = new byte[(int) partSize];
            randomAccessFile.read(partContent, 0, (int) partSize);

            UploadPartRequest uploadPartRequest = new UploadPartRequest(mBucketName, objectKey, context.getUploadId(), i + 1);
            uploadPartRequest.setPartContent(partContent);
            uploadPartRequest.setMd5Digest(BinaryUtil.calculateBase64Md5(partContent));

            OSSAsyncTask task = encryptionClient.asyncUploadPart(uploadPartRequest, context, uploadPartsCallback);
            task.waitUntilFinished();
            assertEquals(uploadPartsCallback.result.getStatusCode(), 200);
            PartETag partETag = new PartETag(i + 1, uploadPartsCallback.result.getETag());
            partETags.add(partETag);
        }

        CompleteMultipartUploadRequest completeMultipartUploadRequest = new CompleteMultipartUploadRequest(mBucketName, objectKey, context.getUploadId(), partETags);
        CompleteMultipartUploadResult completeMultipartUploadResult = encryptionClient.completeMultipartUpload(completeMultipartUploadRequest);
        assertEquals(completeMultipartUploadResult.getStatusCode(), 200);

        GetObjectRequest get = new GetObjectRequest(mBucketName, objectKey);
        OSSAsyncTask getTask = encryptionClient.asyncGetObject(get, getCallback);
        getTask.waitUntilFinished();

        byte[] content = IOUtils.readStreamAsBytesArray(getCallback.result.getObjectContent());

        FileInputStream fileInputStream = new FileInputStream(filePath);
        byte[] originContent = IOUtils.readStreamAsBytesArray(fileInputStream);

        assertEquals(BinaryUtil.calculateBase64Md5(content), BinaryUtil.calculateBase64Md5(originContent));
    }

    @Test
    public void testResumableDownloadObject() throws IOException, ClientException, ServiceException {
        OSSTestConfig.TestPutCallback putCallback = new OSSTestConfig.TestPutCallback();

        final String objectKey = "file10m.jpg";
        PutObjectRequest put = new PutObjectRequest(mBucketName, objectKey,
                FILE_DIR + "file10m");
        OSSAsyncTask putTask = encryptionClient.asyncPutObject(put, putCallback);
        putTask.waitUntilFinished();
        assertEquals(putCallback.result.getStatusCode(), 200);

        String downloadPath = FILE_DIR + "download";
        File downloadFile = new File(downloadPath);
        if (!downloadFile.exists()) {
            downloadFile.mkdirs();
        }
        downloadPath = downloadPath + "/file10m";
        ResumableDownloadRequest downloadRequest = new ResumableDownloadRequest(mBucketName, objectKey, downloadPath);
        ResumableDownloadResult downloadResult = encryptionClient.syncResumableDownload(downloadRequest);
        assertEquals(downloadResult.getStatusCode(), 200);

        assertEquals(BinaryUtil.calculateBase64Md5(downloadPath), BinaryUtil.calculateBase64Md5(FILE_DIR + "file10m"));
    }

    @Test
    public void testResumableDownloadObjectWithCRC() throws IOException, ClientException, ServiceException {
        OSSTestConfig.TestPutCallback putCallback = new OSSTestConfig.TestPutCallback();

        final String objectKey = "file10m.jpg";
        PutObjectRequest put = new PutObjectRequest(mBucketName, objectKey,
                FILE_DIR + "file10m");
        OSSAsyncTask putTask = encryptionClient.asyncPutObject(put, putCallback);
        putTask.waitUntilFinished();
        assertEquals(putCallback.result.getStatusCode(), 200);

        String downloadPath = FILE_DIR + "download";
        File downloadFile = new File(downloadPath);
        if (!downloadFile.exists()) {
            downloadFile.mkdirs();
        }
        downloadPath = downloadPath + "/file10m";
        ResumableDownloadRequest downloadRequest = new ResumableDownloadRequest(mBucketName, objectKey, downloadPath);
        downloadRequest.setCRC64(OSSRequest.CRC64Config.YES);
        ResumableDownloadResult downloadResult = encryptionClient.syncResumableDownload(downloadRequest);
        assertEquals(downloadResult.getStatusCode(), 200);

        assertEquals(BinaryUtil.calculateBase64Md5(downloadPath), BinaryUtil.calculateBase64Md5(FILE_DIR + "file10m"));
    }

    @Test
    public void testResumableDownloadObjectWithRange() throws IOException, ClientException, ServiceException {
        OSSTestConfig.TestPutCallback putCallback = new OSSTestConfig.TestPutCallback();
        final long start = 200 * 1024;
        final long end = 1000 * 1024;

        final String objectKey = "file10m.jpg";
        PutObjectRequest put = new PutObjectRequest(mBucketName, objectKey,
                FILE_DIR + "file10m");
        OSSAsyncTask putTask = encryptionClient.asyncPutObject(put, putCallback);
        putTask.waitUntilFinished();
        assertEquals(putCallback.result.getStatusCode(), 200);

        String downloadPath = FILE_DIR + "download";
        File downloadFile = new File(downloadPath);
        if (!downloadFile.exists()) {
            downloadFile.mkdirs();
        }
        downloadPath = downloadPath + "/file10m";
        ResumableDownloadRequest downloadRequest = new ResumableDownloadRequest(mBucketName, objectKey, downloadPath);
        downloadRequest.setRange(new Range(start, end));
        ResumableDownloadResult downloadResult = encryptionClient.syncResumableDownload(downloadRequest);
        assertEquals(downloadResult.getStatusCode(), 200);

        FileInputStream fileInputStream = new FileInputStream(FILE_DIR + "file1m");
        byte[] originContent = IOUtils.readStreamAsBytesArray(fileInputStream);
        originContent = Arrays.copyOfRange(originContent, (int)start, (int)end);

        assertEquals(BinaryUtil.calculateBase64Md5(downloadPath), BinaryUtil.calculateBase64Md5(originContent));
    }
}
