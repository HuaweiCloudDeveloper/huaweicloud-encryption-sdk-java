package com.huaweicloud.encryptionsdk.model;

import com.huaweicloud.encryptionsdk.common.Constants;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.CipherTamperedException;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.handler.CipherHandler;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;


/**
 * @ClassName CipherHeader
 * @description:
 */
public class CipherHeader {

    private static final String CACHE_ID_ALGORITHM_SM3 = "SM3";


    private byte version = Constants.VERSION;

    private short algorithmId;

    private CryptoAlgorithm algorithm;

    private short encryptionContextByteLength;

    private byte[] encryptionContextByte;

    private byte contentType;

    private Map<String, String> encryptionContext;

    private List<CiphertextDataKey> ciphertextDataKeys;

    private byte cipherDataKeySize;

    private byte ivLength;

    private short headerTagLength;

    private byte[] headerTag;

    private byte[] iv;

    private int contentLength;

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public int getContentLength() {
        return contentLength;
    }

    public void setContentLength(int contentLength) {
        this.contentLength = contentLength;
    }

    public short getHeaderTagLength() {
        return headerTagLength;
    }

    public byte[] getHeaderTag() {
        return headerTag;
    }

    public CryptoAlgorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(CryptoAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    public void setEncryptionContext(Map<String, String> encryptionContext) {
        this.encryptionContext = encryptionContext;
    }

    public List<CiphertextDataKey> getCiphertextDataKeys() {
        return ciphertextDataKeys;
    }

    public void setCiphertextDataKeys(List<CiphertextDataKey> ciphertextDataKeys) {
        this.ciphertextDataKeys = ciphertextDataKeys;
    }

    public CipherHeader() {
    }

    public CipherHeader(CryptoAlgorithm algorithm, Map<String, String> encryptionContext, List<CiphertextDataKey> ciphertextDataKeys, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchProviderException {
        this.algorithm = algorithm;
        this.algorithmId = algorithm.getValue();
        this.encryptionContext = encryptionContext;
        this.encryptionContextByte = Utils.serializeContext(encryptionContext);
        this.encryptionContextByteLength = (short) encryptionContextByte.length;
        this.contentType = 1;
        this.ciphertextDataKeys = ciphertextDataKeys;
        this.cipherDataKeySize = (byte) ciphertextDataKeys.size();
        this.ivLength = (byte) algorithm.getIvLen();
        calculateTag(secretKey);
    }

    private void calculateTag(SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchProviderException {
        byte[] headerFieldsBytes = serializeAuthenticatedFields();
        if (algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING) {
            headerTag = getDigest(headerFieldsBytes);
            headerTagLength = (short) headerTag.length;
            return;
        }
        CipherHandler cipherHandler = new CipherHandler(algorithm, secretKey, Cipher.ENCRYPT_MODE);
        byte[] headerTagByte = cipherHandler.cipherHeaderData(new byte[0], headerFieldsBytes, Constants.NUM_0, Constants.NUM_0);
        int ivLen = cipherHandler.getIv().length;
        byte[] message = new byte[ivLen + headerTagByte.length];
        System.arraycopy(cipherHandler.getIv(), Constants.NUM_0, message, Constants.NUM_0, ivLen);
        System.arraycopy(headerTagByte, Constants.NUM_0, message, ivLen, headerTagByte.length);
        headerTag = message;
        headerTagLength = (short) headerTag.length;
    }

    private byte[] getDigest(byte[] bytes) throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        MessageDigest digest = MessageDigest.getInstance(CACHE_ID_ALGORITHM_SM3, BouncyCastleProvider.PROVIDER_NAME);
        if (bytes.length == 0) {
            digest.update((byte) 0);
        } else {
            digest.update(bytes);
        }
        return digest.digest();
    }

    public byte[] serializeAuthenticatedFields() {
        try (ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
             DataOutputStream dataStream = new DataOutputStream(outBytes)) {
            dataStream.writeByte(version);

            dataStream.writeShort(algorithmId);

            dataStream.writeShort(encryptionContextByteLength);
            dataStream.write(encryptionContextByte);

            dataStream.writeByte(cipherDataKeySize);

            for (CiphertextDataKey dataKey : ciphertextDataKeys) {
                dataStream.write(dataKey.toByteArray());
            }

            dataStream.writeByte(contentType);

            dataStream.writeByte(ivLength);
            return outBytes.toByteArray();
        } catch (IOException e) {
            throw new HuaweicloudException(ErrorMessage.SERIALIZE_EXCEPTION.getMessage(), e);
        }
    }

    public CipherHeader deserializeAuthenticatedFields(DataInputStream dataStream) {

        try {
            version = dataStream.readByte();
            if (version == 1) {
                algorithmId = dataStream.readShort();
                this.algorithm = CryptoAlgorithm.getAlgorithm(algorithmId);
                if (this.algorithm == null) {
                    throw new HuaweicloudException(ErrorMessage.CIPHER_TEXT_CHANGED_ERROR.getMessage() + ",algorithm id is: " + algorithmId);
                }
                encryptionContextByteLength = dataStream.readShort();
                encryptionContextByte = new byte[encryptionContextByteLength];
                dataStream.read(encryptionContextByte);
                this.encryptionContext = Utils.deserializeContext(encryptionContextByte);

                this.cipherDataKeySize = dataStream.readByte();
                if (this.cipherDataKeySize < 0) {
                    throw new HuaweicloudException(ErrorMessage.NOT_FOUND_CIPHER_TEXT_DATA_KEY.getMessage());
                }
                this.ciphertextDataKeys = new ArrayList<>(cipherDataKeySize);
                int ciphertextDataKeyCount = 0;
                while (ciphertextDataKeyCount < cipherDataKeySize) {
                    CiphertextDataKey ciphertextDataKey = new CiphertextDataKey();
                    ciphertextDataKey.byteArrayToBean(dataStream);
                    ciphertextDataKeys.add(ciphertextDataKey);
                    ciphertextDataKeyCount++;
                }

                contentType = dataStream.readByte();
                ivLength = dataStream.readByte();
                headerTagLength = dataStream.readShort();
                headerTag = new byte[headerTagLength];
                dataStream.read(headerTag);
            }
            return this;
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.DESERIALIZE_EXCEPTION.getMessage(), e);
        }


    }

    public void verifyHeader(CipherHandler cipherHandler) {
        try {
            this.headerTag = getHeaderTag();
            byte[] headerFieldsBytes = serializeAuthenticatedFields();
            if (algorithm == CryptoAlgorithm.SM4_128_CBC_PADDING) {
                byte[] digest = getDigest(headerFieldsBytes);
                String encryptHeaderAuthTag = Utils.bytesToHex(headerTag);
                String decryptHeaderAuthTag = Utils.bytesToHex(digest);
                if (Utils.isEmpty(encryptHeaderAuthTag) && Utils.isEmpty(decryptHeaderAuthTag)) {
                    return;
                }
                if (Utils.isEmpty(encryptHeaderAuthTag) || Utils.isEmpty(decryptHeaderAuthTag)) {
                    throw new CipherTamperedException(ErrorMessage.TAMPERED_EXCEPTION.getMessage());
                }
                if (!encryptHeaderAuthTag.equals(decryptHeaderAuthTag)) {
                    throw new CipherTamperedException(ErrorMessage.TAMPERED_EXCEPTION.getMessage());
                }
                return;
            }
            cipherHandler.cipherHeaderData(headerTag, headerFieldsBytes, algorithm.getIvLen(), getHeaderTag().length - algorithm.getIvLen());
        } catch (Exception e) {
            throw new CipherTamperedException(ErrorMessage.TAMPERED_EXCEPTION.getMessage(), e);
        }
    }

    public byte[] serializeFileFields() {
        try (ByteArrayOutputStream outBytes = new ByteArrayOutputStream();
             DataOutputStream dataStream = new DataOutputStream(outBytes)) {
            dataStream.write(iv);
            dataStream.writeLong(contentLength);
            return outBytes.toByteArray();
        } catch (IOException e) {
            throw new HuaweicloudException(ErrorMessage.SERIALIZE_EXCEPTION.getMessage(), e);
        }
    }

    public int getFileHeaderLength(CryptoAlgorithm algorithm) {
        return algorithm.getIvLen() + Long.SIZE / Byte.SIZE;
    }

    public void deserializeFileFields(byte[] headerBytes, CryptoAlgorithm algorithm) {
        this.iv = Arrays.copyOfRange(headerBytes, 0, algorithm.getIvLen());
        this.contentLength = (int) Utils.byteToLong(Arrays.copyOfRange(headerBytes, algorithm.getIvLen(), headerBytes.length));
    }
}
