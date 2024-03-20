package com.alibaba.sdk.android.oss.model;

import android.net.Uri;

import java.io.InputStream;

public class EncryptedPutObjectRequest extends PutObjectRequest {

    private InputStream content;
    private long contentLength;

    public EncryptedPutObjectRequest(String bucketName, String objectKey, String uploadFilePath) {
        super(bucketName, objectKey, uploadFilePath);
    }

    public EncryptedPutObjectRequest(String bucketName, String objectKey, String uploadFilePath, ObjectMetadata metadata) {
        super(bucketName, objectKey, uploadFilePath, metadata);
    }

    public EncryptedPutObjectRequest(String bucketName, String objectKey, byte[] uploadData) {
        super(bucketName, objectKey, uploadData);
    }

    public EncryptedPutObjectRequest(String bucketName, String objectKey, byte[] uploadData, ObjectMetadata metadata) {
        super(bucketName, objectKey, uploadData, metadata);
    }

    public EncryptedPutObjectRequest(String bucketName, String objectKey, Uri uploadUri) {
        super(bucketName, objectKey, uploadUri);
    }

    public EncryptedPutObjectRequest(String bucketName, String objectKey, Uri uploadUri, ObjectMetadata metadata) {
        super(bucketName, objectKey, uploadUri, metadata);
    }

    public InputStream getContent() {
        return content;
    }

    public void setContent(InputStream content) {
        this.content = content;
    }

    public long getContentLength() {
        return contentLength;
    }

    public void setContentLength(long contentLength) {
        this.contentLength = contentLength;
    }
}
