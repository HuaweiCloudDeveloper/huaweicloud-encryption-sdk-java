package com.huaweicloud.encryptionsdk.handler;

import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.CipherBody;
import com.huaweicloud.encryptionsdk.model.CipherHeader;
import com.huaweicloud.encryptionsdk.model.DataMaterials;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * @description: 默认序列化实现
 */
public class DefaultSerializeHandler implements SerializeHandler {


    @Override
    public byte[] serialize(DataMaterials dataMaterials) {
        CipherBody cipherBody = dataMaterials.getCipherBody();
        byte[] headers = dataMaterials.getHeaders().serializeAuthenticatedFields();
        byte[] headerTag = dataMaterials.getHeaders().getHeaderTag();
        ByteBuffer result = ByteBuffer.allocate(cipherBody.getTotalLength() + headers.length + Short.SIZE / Byte.SIZE + headerTag.length);
        result.put(headers);
        result.putShort(dataMaterials.getHeaders().getHeaderTagLength());
        result.put(headerTag);
        result.put(cipherBody.toByteArray());
        return result.array();
    }

    @Override
    public DataMaterials deserialize(byte[] cipherData) {
        try (ByteArrayInputStream outBytes = new ByteArrayInputStream(cipherData);
             DataInputStream dataStream = new DataInputStream(outBytes)) {
            CipherHeader cipherHeader = new CipherHeader().deserializeAuthenticatedFields(dataStream);
            CipherBody cipherBody = null;
            if (dataStream.available() > 0) {
                cipherBody = new CipherBody().deserialize(dataStream, cipherHeader.getAlgorithm());
            }
            return new DataMaterials(cipherBody, cipherHeader);
        } catch (IOException e) {
            throw new HuaweicloudException(ErrorMessage.DESERIALIZE_EXCEPTION.getMessage(), e);
        }


    }

}
