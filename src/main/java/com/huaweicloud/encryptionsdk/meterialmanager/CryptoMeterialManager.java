package com.huaweicloud.encryptionsdk.meterialmanager;

import com.huaweicloud.encryptionsdk.keyrings.Keyring;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import org.apache.commons.codec.DecoderException;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;

/**
 * @description: 数据密钥管理类，获取数据密钥，缓存等操作
 */

public interface CryptoMeterialManager {

    DataKeyMaterials getMaterialsForEncrypt(Keyring keyring, DataKeyMaterials dataKeyMaterials, long plaintTextLength)
        throws NoSuchAlgorithmException, IOException, DecoderException, ExecutionException, InterruptedException;

    DataKeyMaterials getMaterialsForDecrypt(Keyring keyring, byte[] cipherText) throws IOException;

    DataKeyMaterials getMaterialsForStreamDecrypt(Keyring keyring, InputStream inputStream) throws IOException;
}
