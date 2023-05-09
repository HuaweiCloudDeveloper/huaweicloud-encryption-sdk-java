package com.huaweicloud.encryptionsdk.meterialmanager;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.common.Constants;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @description: 本地生成数据密钥
 */
public class LocalDataKeyGenerate implements DataKeyGenerate {

    private static final String KEY_ALGORITHM_SM4 = "SM4";
    private static final String KEY_ALGORITHM_AES = "AES";

    @Override
    public void dataKeyGenerate(HuaweiConfig huaweiConfig, DataKeyMaterials dataKeyMaterials) throws NoSuchAlgorithmException {
        CryptoAlgorithm algorithm = huaweiConfig.getCryptoAlgorithm();
        String[] keySpecArr = algorithm.getKeySpec().split(Constants.KEY_SPEC_DELIMITER);
        String keSpec = keySpecArr[0];
        if (KEY_ALGORITHM_SM4.equalsIgnoreCase(keSpec)) {
            keSpec = KEY_ALGORITHM_AES;
        }
        KeyGenerator keyGenerator = KeyGenerator.getInstance(keSpec);
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        keyGenerator.init(algorithm.getKeyLen() * 8, secureRandom);
        SecretKey secretKey = keyGenerator.generateKey();
        dataKeyMaterials.setPlaintextDataKey(secretKey);
    }
}
