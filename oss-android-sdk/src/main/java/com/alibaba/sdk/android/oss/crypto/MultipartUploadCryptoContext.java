package com.alibaba.sdk.android.oss.crypto;

import java.io.Serializable;

public class MultipartUploadCryptoContext implements Serializable {

    private String uploadId;
    private ContentCryptoMaterial cekMaterial;
    private long partSize;
    private long dataSize;

    public MultipartUploadCryptoContext() {
        partSize = 0;
        dataSize = 0;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int)partSize;
        result = prime * result + (int)dataSize;
        result = prime * result + ((uploadId == null) ? 0 : uploadId.hashCode());
        result = prime * result + ((cekMaterial == null) ? 0 : cekMaterial.hashCode());
        return result;
    }

    public void setPartSize(long partSize) {
        this.partSize = partSize;
    }

    public void setDataSize(long dataSize) {
        this.dataSize = dataSize;
    }

    public long getDataSize() {
        return dataSize;
    }

    public long getPartSize() {
        return partSize;
    }

    public void setUploadId(String uploadId) {
        this.uploadId = uploadId;
    }

    public String getUploadId() {
        return uploadId;
    }

    public void setContentCryptoMaterial(ContentCryptoMaterial cekMaterial) {
        this.cekMaterial = cekMaterial;
    }

    /**
     * @return the content encrypting cryptographic material for the multi-part
     *         uploads.
     */
    public ContentCryptoMaterial getContentCryptoMaterial() {
        return cekMaterial;
    }
}
