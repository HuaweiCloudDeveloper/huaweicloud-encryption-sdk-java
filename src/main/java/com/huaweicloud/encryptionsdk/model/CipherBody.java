package com.huaweicloud.encryptionsdk.model;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;

import java.io.DataInputStream;
import java.io.IOException;

/**
 * @author zc
 * @ClassName CipherBody
 * @description:
 * @datetime 2022年 09月 22日 15:29
 */
public class CipherBody {

    private byte[] iv;

    private byte[] encryptedContent;

    private long encryptedContentLength;

    private byte[] authTag;

    public CipherBody(byte[] iv, byte[] encryptedContent, long encryptedContentLength, byte[] authTag) {
        this.iv = iv;
        this.encryptedContent = encryptedContent;
        this.encryptedContentLength = encryptedContentLength;
        this.authTag = authTag;
    }

    public CipherBody() {
    }

    public int getTotalLength() {
        return iv.length + encryptedContent.length + Long.SIZE / Byte.SIZE + authTag.length;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public byte[] getEncryptedContent() {
        return encryptedContent;
    }

    public void setEncryptedContent(byte[] encryptedContent) {
        this.encryptedContent = encryptedContent;
    }

    public Long getEncryptedContentLength() {
        return encryptedContentLength;
    }

    public void setEncryptedContentLength(Long encryptedContentLength) {
        this.encryptedContentLength = encryptedContentLength;
    }

    public byte[] getAuthTag() {
        return authTag;
    }

    public void setAuthTag(byte[] authTag) {
        this.authTag = authTag;
    }

    public byte[] toByteArray() {
        int offset = 0;
        byte[] bytes = new byte[getTotalLength()];
        System.arraycopy(iv, 0, bytes, 0, iv.length);
        offset += iv.length;
        byte[] encryptedContentLengthBytes = Utils.longToByte(encryptedContentLength);
        System.arraycopy(encryptedContentLengthBytes, 0, bytes, offset, encryptedContentLengthBytes.length);
        offset += encryptedContentLengthBytes.length;
        System.arraycopy(encryptedContent, 0, bytes, offset, encryptedContent.length);
        offset += encryptedContent.length;
        System.arraycopy(authTag, 0, bytes, offset, authTag.length);
        return bytes;
    }

    public CipherBody deserialize(DataInputStream dataStream, CryptoAlgorithm algorithm) throws IOException {
        iv = new byte[algorithm.getIvLen()];
        int readIv = dataStream.read(iv);
        if (readIv != iv.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
        byte[] encryptedContentLengthBytes = new byte[Long.SIZE / Byte.SIZE];
        int read = dataStream.read(encryptedContentLengthBytes);
        if (read != encryptedContentLengthBytes.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
        encryptedContentLength = Utils.byteToLong(encryptedContentLengthBytes);
        encryptedContent = new byte[(int) encryptedContentLength];
        int readContent = dataStream.read(encryptedContent);
        if (readContent != encryptedContent.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
        if (algorithm != CryptoAlgorithm.SM4_128_CBC_PADDING) {
            authTag = new byte[algorithm.getTagLen()];
        } else {
            authTag = new byte[0];
        }
        int readAuthTag = dataStream.read(authTag);
        if (readAuthTag != authTag.length) {
            throw new HuaweicloudException(ErrorMessage.SOURCE_FILE_INVALID.getMessage());
        }
        return this;
    }
}
