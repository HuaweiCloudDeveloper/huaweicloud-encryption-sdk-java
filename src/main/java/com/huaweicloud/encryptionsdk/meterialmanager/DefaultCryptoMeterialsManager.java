package com.huaweicloud.encryptionsdk.meterialmanager;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.handler.DefaultSerializeHandler;
import com.huaweicloud.encryptionsdk.keyrings.Keyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.model.DataMaterials;
import com.huaweicloud.encryptionsdk.model.enums.DataKeyGenerateType;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import org.apache.commons.codec.DecoderException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;

/**
 * @description: 默认数据密钥管理器器
 */
public class DefaultCryptoMeterialsManager implements CryptoMeterialManager {

    private HuaweiConfig huaweiConfig;

    public DefaultCryptoMeterialsManager(HuaweiConfig huaweiConfig) {
        this.huaweiConfig = huaweiConfig;

    }

    public DefaultCryptoMeterialsManager() {

    }

    @Override
    public DataKeyMaterials getMaterialsForEncrypt(Keyring keyring, DataKeyMaterials dataKeyMaterials, long plaintTextLength) throws NoSuchAlgorithmException, IOException, ExecutionException, InterruptedException, DecoderException {
        DataKeyGenerate dataKeyGenerate;
        if (keyring instanceof KMSKeyring) {
            dataKeyGenerate = DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.KMS_GENERATE);
            ((KMSKeyring) keyring).setHuaweiConfig(huaweiConfig);
        } else {
            dataKeyGenerate = DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.LOCAL_GENERATE);
        }
        dataKeyGenerate.dataKeyGenerate(huaweiConfig, dataKeyMaterials);
        return keyring.encryptDataKey(dataKeyMaterials);
    }

    @Override
    public DataKeyMaterials getMaterialsForDecrypt(Keyring keyring, byte[] cipherText) throws IOException {
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        DataMaterials dataMaterials = new DefaultSerializeHandler().deserialize(cipherText);
        dataKeyMaterials.setCiphertextDataKeys(dataMaterials.getHeaders().getCiphertextDataKeys());
        dataKeyMaterials.setCryptoAlgorithm(dataMaterials.getHeaders().getAlgorithm());
        dataKeyMaterials.setEncryptionContexts(dataMaterials.getHeaders().getEncryptionContext());
        if (keyring instanceof KMSKeyring) {
            ((KMSKeyring) keyring).setHuaweiConfig(huaweiConfig);
        }
        return keyring.decryptDataKey(dataKeyMaterials);
    }

    @Override
    public DataKeyMaterials getMaterialsForStreamDecrypt(Keyring keyring, InputStream inputStream) throws IOException {
        byte[] lengthByte = new byte[Short.SIZE / Byte.SIZE];
        inputStream.read(lengthByte);
        ByteBuffer buffer = ByteBuffer.allocate(lengthByte.length).put(lengthByte);
        buffer.flip();
        short length = buffer.getShort();
        byte[] bytes = new byte[length];
        inputStream.read(bytes);
        DataMaterials dataMaterials = new DefaultSerializeHandler().deserialize(bytes);
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyMaterials.setCiphertextDataKeys(dataMaterials.getHeaders().getCiphertextDataKeys());
        dataKeyMaterials.setCryptoAlgorithm(dataMaterials.getHeaders().getAlgorithm());
        dataKeyMaterials.setEncryptionContexts(dataMaterials.getHeaders().getEncryptionContext());
        if (keyring instanceof KMSKeyring) {
            ((KMSKeyring) keyring).setHuaweiConfig(huaweiConfig);
        }
        return keyring.decryptDataKey(dataKeyMaterials);
    }

}
