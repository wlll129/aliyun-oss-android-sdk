package com.alibaba.sdk.android.oss.crypto;

import android.content.Context;
import android.os.ParcelFileDescriptor;

import com.alibaba.sdk.android.oss.ClientException;
import com.alibaba.sdk.android.oss.ServiceException;
import com.alibaba.sdk.android.oss.callback.OSSCompletedCallback;
import com.alibaba.sdk.android.oss.common.OSSHeaders;
import com.alibaba.sdk.android.oss.common.OSSLog;
import com.alibaba.sdk.android.oss.common.io.RepeatableFileInputStream;
import com.alibaba.sdk.android.oss.common.utils.BinaryUtil;
import com.alibaba.sdk.android.oss.common.utils.CRC64;
import com.alibaba.sdk.android.oss.internal.OSSAsyncTask;
import com.alibaba.sdk.android.oss.model.EncryptedPutObjectRequest;
import com.alibaba.sdk.android.oss.model.GetObjectRequest;
import com.alibaba.sdk.android.oss.model.GetObjectResult;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadRequest;
import com.alibaba.sdk.android.oss.model.InitiateMultipartUploadResult;
import com.alibaba.sdk.android.oss.model.ObjectMetadata;
import com.alibaba.sdk.android.oss.model.PutObjectRequest;
import com.alibaba.sdk.android.oss.model.PutObjectResult;
import com.alibaba.sdk.android.oss.model.Range;
import com.alibaba.sdk.android.oss.model.UploadPartRequest;
import com.alibaba.sdk.android.oss.model.UploadPartResult;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.zip.CheckedInputStream;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public abstract class CryptoModuleBase implements CryptoModule {

    protected static final int DEFAULT_BUFFER_SIZE = 1024 * 2;

    protected final EncryptionMaterials encryptionMaterials;
    protected final CryptoConfiguration cryptoConfig;
    protected final CryptoScheme contentCryptoScheme;
    protected final Context context;
    protected final OSSDirect direct;

    public CryptoModuleBase(OSSDirect direct,
                            EncryptionMaterials encryptionMaterials,
                            CryptoConfiguration cryptoConfig,
                            Context context) {
        this.direct = direct;
        this.encryptionMaterials = encryptionMaterials;
        this.cryptoConfig = cryptoConfig;
        this.contentCryptoScheme = CryptoScheme.getCryptoScheme(cryptoConfig.getContentCryptoMode());
        this.context = context;
    }

    public final static CryptoModuleBase getCryptoModuleBase(OSSDirect direct,
                                                             ContentCryptoMode contentCryptoMode,
                                                             EncryptionMaterials encryptionMaterials,
                                                             CryptoConfiguration cryptoConfig,
                                                             Context context) {
        switch (contentCryptoMode) {
            case AES_CTR_MODE:
            default:
                return new CryptoModuleAesCtr(direct, encryptionMaterials, cryptoConfig, context);
        }
    }

    @Override
    public PutObjectResult putObjectSecurely(PutObjectRequest req) throws ClientException, ServiceException {
        EncryptedPutObjectRequest encryptedPutObjectRequest = convertToEncryptedPutObjectRequest(req);

        ContentCryptoMaterial cekMaterial = buildContentCryptoMaterials();

        ObjectMetadata meta = updateMetadataWithContentCryptoMaterial(req.getMetadata(), cekMaterial);
        encryptedPutObjectRequest.setMetadata(meta);

        PutObjectRequest wrappedReq = wrapPutRequestWithCipher(encryptedPutObjectRequest, cekMaterial);

        return direct.putObject(wrappedReq);
    }

    @Override
    public OSSAsyncTask<PutObjectResult> asyncPutObjectSecurely(PutObjectRequest request, OSSCompletedCallback<PutObjectRequest, PutObjectResult> completedCallback) {
        try {
            EncryptedPutObjectRequest encryptedPutObjectRequest = convertToEncryptedPutObjectRequest(request);

            ContentCryptoMaterial cekMaterial = buildContentCryptoMaterials();
            ObjectMetadata meta = updateMetadataWithContentCryptoMaterial(request.getMetadata(), cekMaterial);
            encryptedPutObjectRequest.setMetadata(meta);

            PutObjectRequest wrappedReq = wrapPutRequestWithCipher(encryptedPutObjectRequest, cekMaterial);
            return direct.asyncPutObject(wrappedReq, completedCallback);
        } catch (ClientException e) {
            OSSLog.logError(e.getMessage());
            completedCallback.onFailure(request, e, null);
        }

        return null;
    }

        /**
         * Returns the given {@link PutObjectRequest} instance but has the content as
         * input stream wrapped with a cipher, and configured with some meta data and
         * user metadata.
         */
    protected final PutObjectRequest wrapPutRequestWithCipher(final EncryptedPutObjectRequest request,
                                                              ContentCryptoMaterial cekMaterial) throws ClientException {
        // Create a new metadata object if there is no metadata already.
        ObjectMetadata metadata = request.getMetadata();
        if (metadata == null) {
            metadata = new ObjectMetadata();
        }

        // update content md5 and length headers.
        updateContentMd5(request, metadata);
        try {
            updateContentLength(request, metadata);
        } catch (IOException e) {
            OSSLog.logError(e.getMessage());
            throw new ClientException(e.getMessage(), e);
        }

        // Create content crypto cipher.
        CryptoCipher cryptoCipher = createCryptoCipherFromContentMaterial(cekMaterial, Cipher.ENCRYPT_MODE, null, 0);

        // Treat all encryption requests as input stream upload requests.
        InputStream inputStream = null;
        long length = 0;
        try {
            if (request.getUploadData() != null) {
                inputStream = new ByteArrayInputStream(request.getUploadData());
                length = request.getUploadData().length;
            } else if (request.getUploadUri() != null) {
                ParcelFileDescriptor parcelFileDescriptor = context.getContentResolver().openFileDescriptor(request.getUploadUri(), "r");
                inputStream = new FileInputStream(parcelFileDescriptor.getFileDescriptor());
                length = parcelFileDescriptor.getStatSize();
            } else if (request.getUploadFilePath() != null) {
                File file = new File(request.getUploadFilePath());
                inputStream = new FileInputStream(file);
                length = file.length();
            }
            if (inputStream instanceof FileInputStream) {
                inputStream = new RepeatableFileInputStream((FileInputStream)inputStream);
            }
            request.setContent(new RenewableCipherInputStream(inputStream, cryptoCipher));
            request.setContentLength(length);
        } catch (Exception e) {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException ex) {
                    throw new ClientException(e.getMessage(), e);
                }
            }
        }

        return request;
    }

    private void updateContentMd5(final PutObjectRequest request, final ObjectMetadata metadata) {
        if (metadata.getContentMD5() != null) {
            metadata.addUserMetadata(CryptoHeaders.CRYPTO_UNENCRYPTION_CONTENT_MD5, metadata.getContentMD5());
            metadata.removeHeader(OSSHeaders.CONTENT_MD5);
        }

        request.setMetadata(metadata);
    }

    private void updateContentLength(final PutObjectRequest request, final ObjectMetadata metadata) throws IOException {
        final long plaintextLength = plaintextLength(request, metadata);
        if (plaintextLength >= 0) {
            metadata.addUserMetadata(CryptoHeaders.CRYPTO_UNENCRYPTION_CONTENT_LENGTH, Long.toString(plaintextLength));
            metadata.setContentLength(plaintextLength);
        }
        request.setMetadata(metadata);
    }

    /**
     * Returns the plaintext length from the request and metadata; or -1 if unknown.
     */
    protected final long plaintextLength(PutObjectRequest request, ObjectMetadata metadata) throws IOException {
        if (request.getUploadFilePath() != null) {
            File file = new File(request.getUploadFilePath());
            return file.length();
        } else if (request.getUploadUri() != null) {
            ParcelFileDescriptor parcelFileDescriptor = null;
            try {
                parcelFileDescriptor = context.getContentResolver().openFileDescriptor(request.getUploadUri(), "r");
                return  parcelFileDescriptor.getStatSize();
            } finally {
                if (parcelFileDescriptor != null) {
                    parcelFileDescriptor.close();
                }
            }
        } else if (request.getUploadData() != null) {
            return request.getUploadData().length;
        }
        return -1;
    }

    @Override
    public GetObjectResult getObjectSecurely(GetObjectRequest req) throws ClientException, ServiceException {
        // Update User-Agent.
//        setUserAgent(req, encryptionClientUserAgent);

        // Adjust range-get
        Range desiredRange = req.getRange();
        Range adjustedCryptoRange = getAdjustedCryptoRange(desiredRange);
        if (adjustedCryptoRange != null) {
            req.setRange(adjustedCryptoRange);
        }

        // Get the object from OSS
        GetObjectResult result = direct.getObject(req);
        result.setObjectContent(new CheckedInputStream(result.getObjectContent(), new CRC64()));

        // Recheck range-get
        String contentRange = (String) result.getMetadata().getRawMetadata().get("Content-Range");
        if (contentRange == null && adjustedCryptoRange != null) {
            desiredRange.setBegin(0);
            desiredRange.setEnd(result.getMetadata().getContentLength() - 1);
            adjustedCryptoRange = new Range(desiredRange.getBegin(), desiredRange.getEnd());
        }

        // Convert OSSObject content with cipher insteam
        try {
            if (hasEncryptionInfo(result.getMetadata())) {
                return decipherWithMetadata(req, desiredRange, adjustedCryptoRange, result);
            }
            GetObjectResult adjustedOSSObject = adjustToDesiredRange(result, desiredRange);
            return adjustedOSSObject;
        } catch (Exception e) {
            throw new ClientException(e);
        }
    }

    @Override
    public OSSAsyncTask<GetObjectResult> asyncGetObjectSecurely(GetObjectRequest request, final OSSCompletedCallback<GetObjectRequest, GetObjectResult> completedCallback) {
        // Adjust range-get
        try {

            final Range desiredRange = request.getRange();
            final Range[] adjustedCryptoRange = {getAdjustedCryptoRange(desiredRange)};
            if (adjustedCryptoRange[0] != null) {
                request.setRange(adjustedCryptoRange[0]);
            }

            // Get the object from OSS
            OSSAsyncTask task = direct.asyncGetObject(request, new OSSCompletedCallback<GetObjectRequest, GetObjectResult>() {
                @Override
                public void onSuccess(GetObjectRequest request, GetObjectResult result) {
                    // Recheck range-get
                    String contentRange = (String) result.getMetadata().getRawMetadata().get("Content-Range");
                    if (contentRange == null && adjustedCryptoRange[0] != null) {
                        desiredRange.setBegin(0);
                        desiredRange.setEnd(result.getMetadata().getContentLength() - 1);
                        adjustedCryptoRange[0] = new Range(desiredRange.getBegin(), desiredRange.getEnd());
                    }

                    try {
                        GetObjectResult adjustedOSSObject = null;
                        // Convert OSSObject content with cipher insteam
                        if (hasEncryptionInfo(result.getMetadata())) {
                            adjustedOSSObject = decipherWithMetadata(request, desiredRange, adjustedCryptoRange[0], result);
                        } else {
                            adjustedOSSObject = adjustToDesiredRange(result, desiredRange);
                        }
                        completedCallback.onSuccess(request, adjustedOSSObject);
                    } catch (ClientException e) {
                        completedCallback.onFailure(request, e, null);
                    }
                }

                @Override
                public void onFailure(GetObjectRequest request, ClientException clientException, ServiceException serviceException) {
                    completedCallback.onFailure(request, clientException, serviceException);
                }
            });
            return task;
        } catch (Exception e) {
            completedCallback.onFailure(request, new ClientException(e), null);
        }
        return null;
    }

    /**
     * Adjustes the range-get start offset to allgn with cipher block.
     */
    Range getAdjustedCryptoRange(Range range) throws ClientException {
        if (range == null) {
            return null;
        }

        if ((range.getBegin() > range.getEnd()) || (range.getBegin() < 0) || (range.getEnd() <= 0)) {
            throw new ClientException("Your input get-range is illegal. + range:" + range.getBegin() + "~" + range.getEnd());
        }

        long begin = getCipherBlockLowerBound(range.getBegin());
        long end = range.getEnd();
        Range adjustedCryptoRange = new Range(begin, end);
        return adjustedCryptoRange;
    }

    private long getCipherBlockLowerBound(long leftmostBytePosition) {
        long cipherBlockSize = CryptoScheme.BLOCK_SIZE;
        long offset = leftmostBytePosition % cipherBlockSize;
        long lowerBound = leftmostBytePosition - offset;
        return lowerBound;
    }

    /**
     * Checks there an encryption info in the metadata.
     */
    public static boolean hasEncryptionInfo(ObjectMetadata metadata) {
        Map<String, String> userMeta = metadata.getUserMetadata();
        return userMeta != null && userMeta.containsKey(CryptoHeaders.CRYPTO_KEY)
                && userMeta.containsKey(CryptoHeaders.CRYPTO_IV);
    }

    protected void safeCloseSource(Closeable is) {
        if (is != null) {
            try {
                is.close();
            } catch (IOException ex) {
            }
        }
    }

    /**
     * Decrypt the encypted object by the metadata achieved.
     */
    protected GetObjectResult decipherWithMetadata(GetObjectRequest req,
                                             Range desiredRange,
                                             Range cryptoRange, GetObjectResult retrieved) throws ClientException {

        // Create ContentCryptoMaterial by parse metadata.
        ContentCryptoMaterial cekMaterial = createContentMaterialFromMetadata(retrieved.getMetadata());

        // Create crypto cipher by contentCryptoMaterial
        CryptoCipher cryptoCipher = createCryptoCipherFromContentMaterial(cekMaterial, Cipher.DECRYPT_MODE, cryptoRange,
                0);

        // Wrap retrieved object with cipherInputStream.
        InputStream objectContent = retrieved.getObjectContent();
        retrieved.setObjectContent(
                new CipherInputStream(objectContent,
                        cryptoCipher,
                        DEFAULT_BUFFER_SIZE));

        // Adjust the output to the desired range of bytes.
        GetObjectResult adjusted = adjustToDesiredRange(retrieved, desiredRange);
        return adjusted;
    }
    /*
     * Builds a new content crypto material for decrypting the object achieved.
     */
    protected ContentCryptoMaterial createContentMaterialFromMetadata(ObjectMetadata meta) throws ClientException {
        Map<String, String> userMeta = meta.getUserMetadata();
        // Encrypted CEK and encrypted IV.
        String b64CEK = userMeta.get(CryptoHeaders.CRYPTO_KEY);
        String b64IV = userMeta.get(CryptoHeaders.CRYPTO_IV);
        if (b64CEK == null || b64IV == null) {
            throw new ClientException("Content encrypted key  or encrypted iv not found.");
        }
        byte[] encryptedCEK = BinaryUtil.fromBase64StringNoWrap(b64CEK);
        byte[] encryptedIV = BinaryUtil.fromBase64StringNoWrap(b64IV);

        // Key wrap algorithm
        final String keyWrapAlgo = userMeta.get(CryptoHeaders.CRYPTO_WRAP_ALG);
        if (keyWrapAlgo == null)
            throw new ClientException("Key wrap algorithm should not be null.");

        // CEK algorithm
        String cekAlgo = userMeta.get(CryptoHeaders.CRYPTO_CEK_ALG);

        // Description
        String mateDescString = userMeta.get(CryptoHeaders.CRYPTO_MATDESC);
        Map<String, String> matDesc = getDescFromJsonString(mateDescString);

        // Decrypt the secured CEK to CEK.
        ContentCryptoMaterialRW contentMaterialRW = new ContentCryptoMaterialRW();
        contentMaterialRW.setEncryptedCEK(encryptedCEK);
        contentMaterialRW.setEncryptedIV(encryptedIV);
        contentMaterialRW.setMaterialsDescription(matDesc);
        contentMaterialRW.setContentCryptoAlgorithm(cekAlgo);
        contentMaterialRW.setKeyWrapAlgorithm(keyWrapAlgo);
        encryptionMaterials.decryptCEK(contentMaterialRW);

        // Convert to read-only object.
        return contentMaterialRW;
    }

    protected static Map<String, String> getDescFromJsonString(String jsonString) throws ClientException {
        Map<String, String> map = new HashMap<String, String>();
        if (jsonString == null) {
            return map;
        }
        try {
            JSONObject obj = new JSONObject(jsonString);
            Iterator iter = obj.keys();
            while (iter.hasNext()) {
                String key = (String) iter.next();
                String value = obj.getString(key);
                map.put(key, value);
            }
            return map;
        } catch (JSONException e) {
            throw new ClientException("Unable to parse Json string:" + "json", e);
        }
    }

    /**
     * Adjusts the retrieved OSSObject so that the object contents contain only the
     * range of bytes desired by the user. Since encrypted contents can only be
     * retrieved in CIPHER_BLOCK_SIZE (16 bytes) chunks, the OSSObject potentially
     * contains more bytes than desired, so this method adjusts the contents range.
     */
    protected final GetObjectResult adjustToDesiredRange(GetObjectResult OSSobject, Range range) throws ClientException {
        if (range == null)
            return OSSobject;

        try {
            InputStream objectContent = OSSobject.getObjectContent();
            InputStream adjustedRangeContents = new AdjustedRangeInputStream(objectContent, range.getBegin(), range.getEnd());
            OSSobject.setObjectContent(adjustedRangeContents);
            return OSSobject;
        } catch (IOException e) {
            throw new ClientException("Error adjusting output to desired byte range: " + e.getMessage());
        }
    }

    @Override
    public InitiateMultipartUploadResult initiateMultipartUploadSecurely(InitiateMultipartUploadRequest request, MultipartUploadCryptoContext context) throws ClientException, ServiceException {
        checkMultipartContext(context);

        // Update User-Agent.
//        setUserAgent(req, encryptionClientUserAgent);

        // Get content crypto material.
        ContentCryptoMaterial cekMaterial = buildContentCryptoMaterials();

        ObjectMetadata metadata = request.getMetadata();
        if (metadata == null) {
            metadata = new ObjectMetadata();
        }

        // Store encryption info in metadata
        metadata = updateMetadataWithContentCryptoMaterial(metadata, cekMaterial);
        metadata = updateMetadataWithUploadContext(metadata, context);
        request.setMetadata(metadata);

        // Fill context
        InitiateMultipartUploadResult result = direct.initMultipartUpload(request);
        context.setUploadId(result.getUploadId());
        context.setContentCryptoMaterial(cekMaterial);

        return result;
    }

    @Override
    public OSSAsyncTask<InitiateMultipartUploadResult> asyncInitMultipartUploadSecurely(InitiateMultipartUploadRequest request, final MultipartUploadCryptoContext context, final OSSCompletedCallback<InitiateMultipartUploadRequest, InitiateMultipartUploadResult> completedCallback) {
        checkMultipartContext(context);

        // Update User-Agent.
//        setUserAgent(req, encryptionClientUserAgent);

        // Get content crypto material.
        final ContentCryptoMaterial cekMaterial;
        try {
            cekMaterial = buildContentCryptoMaterials();
        } catch (ClientException e) {
            OSSLog.logError(e.getMessage());
            completedCallback.onFailure(request, e, null);
            return null;
        }

        ObjectMetadata metadata = request.getMetadata();
        if (metadata == null) {
            metadata = new ObjectMetadata();
        }

        // Store encryption info in metadata
        metadata = updateMetadataWithContentCryptoMaterial(metadata, cekMaterial);
        metadata = updateMetadataWithUploadContext(metadata, context);
        request.setMetadata(metadata);

        // Fill context
        OSSAsyncTask task = direct.asyncInitMultipartUpload(request, new OSSCompletedCallback<InitiateMultipartUploadRequest, InitiateMultipartUploadResult>() {
            @Override
            public void onSuccess(InitiateMultipartUploadRequest request, InitiateMultipartUploadResult result) {
                context.setUploadId(result.getUploadId());
                context.setContentCryptoMaterial(cekMaterial);
                completedCallback.onSuccess(request, result);
            }

            @Override
            public void onFailure(InitiateMultipartUploadRequest request, ClientException clientException, ServiceException serviceException) {
                completedCallback.onFailure(request, clientException, serviceException);
            }
        });

        return task;
    }

    @Override
    public UploadPartResult uploadPartSecurely(UploadPartRequest request, MultipartUploadCryptoContext context) throws ClientException {
        UploadPartResult result = null;

        // Check partsize and context
        checkMultipartContext(context);
        if (!context.getUploadId().equals(request.getUploadId())) {
            throw new ClientException("The multipartUploadCryptoContextcontext input upload id is invalid."
                    + "context uploadid:" + context.getUploadId() + ",uploadRequest uploadid:" + request.getUploadId());
        }

        // Update User-Agent.
//        setUserAgent(req, encryptionClientUserAgent);

        // Create CryptoCipher
        long offset = context.getPartSize() * (request.getPartNumber() - 1);
        long skipBlock = offset / CryptoScheme.BLOCK_SIZE;
        CryptoCipher cryptoCipher = createCryptoCipherFromContentMaterial(context.getContentCryptoMaterial(),
                Cipher.ENCRYPT_MODE, null, skipBlock);

        // Wrap InputStram to CipherInputStream
        try {
            request.setPartContent(cryptoCipher.update(request.getPartContent(), 0, request.getPartContent().length));
            request.setMd5Digest(BinaryUtil.calculateBase64Md5(request.getPartContent()));
            result = direct.uploadPart(request);
        } catch (Exception e) {
            throw new ClientException(e.getMessage(), e);
        }
        return result;
    }

    @Override
    public OSSAsyncTask<UploadPartResult> asyncUploadPartSecurely(UploadPartRequest request, MultipartUploadCryptoContext context, OSSCompletedCallback<UploadPartRequest, UploadPartResult> completedCallback) {
        // Check partsize and context
        checkMultipartContext(context);
        if (!context.getUploadId().equals(request.getUploadId())) {
            ClientException clientException = new ClientException("The multipartUploadCryptoContextcontext input upload id is invalid."
                    + "context uploadid:" + context.getUploadId() + ",uploadRequest uploadid:" + request.getUploadId());
            completedCallback.onFailure(request, clientException, null);
        }

        // Update User-Agent.
//        setUserAgent(req, encryptionClientUserAgent);

        // Create CryptoCipher
        long offset = context.getPartSize() * (request.getPartNumber() - 1);
        long skipBlock = offset / CryptoScheme.BLOCK_SIZE;
        CryptoCipher cryptoCipher = null;
        try {
            cryptoCipher = createCryptoCipherFromContentMaterial(context.getContentCryptoMaterial(),
                    Cipher.ENCRYPT_MODE, null, skipBlock);
        } catch (ClientException e) {
            completedCallback.onFailure(request, e, null);
        }

        // Wrap InputStram to CipherInputStream
        request.setPartContent(cryptoCipher.update(request.getPartContent(), 0, request.getPartContent().length));
        request.setMd5Digest(BinaryUtil.calculateBase64Md5(request.getPartContent()));
        OSSAsyncTask task = direct.asyncUploadPart(request, completedCallback);

        return task;
    }

    private EncryptedPutObjectRequest convertToEncryptedPutObjectRequest(PutObjectRequest request) {
        EncryptedPutObjectRequest encryptedPutObjectRequest = new EncryptedPutObjectRequest(request.getBucketName(), request.getObjectKey(), request.getUploadFilePath());
        encryptedPutObjectRequest.setCallbackParam(request.getCallbackParam());
        encryptedPutObjectRequest.setCallbackVars(request.getCallbackVars());
        encryptedPutObjectRequest.setCRC64(request.getCRC64());
        encryptedPutObjectRequest.setMetadata(request.getMetadata());
        encryptedPutObjectRequest.setProgressCallback(request.getProgressCallback());
        encryptedPutObjectRequest.setRetryCallback(request.getRetryCallback());
        encryptedPutObjectRequest.setIsAuthorizationRequired(request.isAuthorizationRequired());
        encryptedPutObjectRequest.setUploadData(request.getUploadData());
        encryptedPutObjectRequest.setUploadUri(request.getUploadUri());

        return encryptedPutObjectRequest;
    }

    abstract byte[] generateIV();
    abstract CryptoCipher createCryptoCipherFromContentMaterial(ContentCryptoMaterial cekMaterial,
                                                                int cipherMode, Range cryptoRange, long skipBlock) throws ClientException;

    protected final ContentCryptoMaterial buildContentCryptoMaterials() throws ClientException {
        // Generate random CEK IV
        byte[] iv = generateIV();
        SecretKey cek = generateCEK();

        // Build content crypto Materials by encryptionMaterials.
        ContentCryptoMaterialRW contentMaterialRW = new ContentCryptoMaterialRW();
        contentMaterialRW.setIV(iv);
        contentMaterialRW.setCEK(cek);
        contentMaterialRW.setContentCryptoAlgorithm(contentCryptoScheme.getContentChiperAlgorithm());
        encryptionMaterials.encryptCEK(contentMaterialRW);

        return contentMaterialRW;
    }

    /**
     * Wraps the inputStream with an crypto cipher.
     */
    private CipherInputStream newOSSCryptoCipherInputStream(PutObjectRequest req, CryptoCipher cryptoCipher) throws ClientException {

        InputStream inputStream = null;
        try {
            if (req.getUploadData() != null) {
                inputStream = new ByteArrayInputStream(req.getUploadData());
            } else if (req.getUploadUri() != null) {
                ParcelFileDescriptor parcelFileDescriptor = context.getContentResolver().openFileDescriptor(req.getUploadUri(), "r");
                inputStream = new FileInputStream(parcelFileDescriptor.getFileDescriptor());
            } else if (req.getUploadFilePath() != null) {
                File file = new File(req.getUploadFilePath());
                inputStream = new FileInputStream(file);
            }
            if (inputStream instanceof FileInputStream) {
                inputStream = new RepeatableFileInputStream((FileInputStream)inputStream);
            }
            return new RenewableCipherInputStream(inputStream, cryptoCipher);
        } catch (Exception e) {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException ex) {
                    throw new ClientException(e.getMessage(), e);
                }
            }
        }
        return null;
    }

    /**
     * Storages the encrytion materials in the object metadata.
     */
    protected final ObjectMetadata updateMetadataWithContentCryptoMaterial(ObjectMetadata metadata, ContentCryptoMaterial contentCryptoMaterial) {
        if (metadata == null)
            metadata = new ObjectMetadata();

        // Put the encrypted content encrypt key into the object meatadata
        byte[] encryptedCEK = contentCryptoMaterial.getEncryptedCEK();
        metadata.addUserMetadata(CryptoHeaders.CRYPTO_KEY, BinaryUtil.toBase64StringNoWrap(encryptedCEK));

        // Put the iv into the object metadata
        byte[] encryptedIV = contentCryptoMaterial.getEncryptedIV();
        metadata.addUserMetadata(CryptoHeaders.CRYPTO_IV, BinaryUtil.toBase64StringNoWrap(encryptedIV));

        // Put the content encrypt key algorithm into the object metadata
        String contentCryptoAlgo = contentCryptoMaterial.getContentCryptoAlgorithm();
        metadata.addUserMetadata(CryptoHeaders.CRYPTO_CEK_ALG, contentCryptoAlgo);

        // Put the key wrap algorithm into the object metadata
        String keyWrapAlgo = contentCryptoMaterial.getKeyWrapAlgorithm();
        metadata.addUserMetadata(CryptoHeaders.CRYPTO_WRAP_ALG, keyWrapAlgo);

        // Put the crypto description into the object metadata
        Map<String, String> materialDesc = contentCryptoMaterial.getMaterialsDescription();
        if (materialDesc != null && materialDesc.size() > 0) {
            JSONObject descJson = new JSONObject(materialDesc);
            String descStr = descJson.toString();
            metadata.addUserMetadata(CryptoHeaders.CRYPTO_MATDESC, descStr);
        }

        return metadata;
    }

    /**
     * Returns a srcret key for encrypting content.
     *
     * @return content encrypt key.
     */
    protected SecretKey generateCEK() throws ClientException {
        KeyGenerator generator;
        final String keygenAlgo = contentCryptoScheme.getKeyGeneratorAlgorithm();
        final int keyLength = contentCryptoScheme.getKeyLengthInBits();
        try {
            generator = KeyGenerator.getInstance(keygenAlgo);
            generator.init(keyLength, cryptoConfig.getSecureRandom());
            SecretKey secretKey = generator.generateKey();
            for (int retry = 0; retry < 9; retry++) {
                secretKey = generator.generateKey();
                if (secretKey.getEncoded()[0] != 0)
                    return secretKey;
            }
            throw new ClientException("Failed to generate secret key");
        } catch (NoSuchAlgorithmException e) {
            throw new ClientException("No such algorithm:" + keygenAlgo + ", " + e.getMessage(), e);
        }
    }

    private void checkMultipartContext(MultipartUploadCryptoContext context) {
        if (context == null) {
            throw new IllegalArgumentException("MultipartUploadCryptoContext should not be null.");
        }

        if (0 != (context.getPartSize() % CryptoScheme.BLOCK_SIZE) || context.getPartSize() <= 0) {
            throw new IllegalArgumentException("MultipartUploadCryptoContext part size is not 16 bytes alignment.");
        }
    }

    /**
     * Add the upload part info into metadata.
     */
    protected final ObjectMetadata updateMetadataWithUploadContext(ObjectMetadata metadata,
                                                                   MultipartUploadCryptoContext context) {
        if (metadata == null) {
            metadata = new ObjectMetadata();
        }
        metadata.addUserMetadata(CryptoHeaders.CRYPTO_PART_SIZE, String.valueOf(context.getPartSize()));
        if (context.getDataSize() > 0) {
            metadata.addUserMetadata(CryptoHeaders.CRYPTO_DATA_SIZE, String.valueOf(context.getDataSize()));
        }
        return metadata;
    }
}
