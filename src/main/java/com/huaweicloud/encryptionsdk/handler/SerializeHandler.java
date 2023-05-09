package com.huaweicloud.encryptionsdk.handler;

import com.huaweicloud.encryptionsdk.model.CipherHeader;
import com.huaweicloud.encryptionsdk.model.DataMaterials;

/**
 * @description: 序列化器
 */
public interface SerializeHandler {

    byte[] serialize(DataMaterials dataMaterials);

    DataMaterials deserialize(byte[] cipherData);

}
