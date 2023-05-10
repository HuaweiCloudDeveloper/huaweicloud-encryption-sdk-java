package com.huawei.encyptionsdk.test;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.meterialmanager.DataKeyGenerate;
import com.huaweicloud.encryptionsdk.meterialmanager.DataKeyGenerateFactory;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.enums.DataKeyGenerateType;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collections;

/**
 * DataKeyGenerateTest
 */
public class DataKeyGenerateTest {
    private static final String ACCESS_KEY = "WN0ETTDULCBZDCPDMBR8";
    private static final String SECRET_ACCESS_KEY = "M7dOePlpneNQmKSVSAIV6Vp2zNtwfoGM3Lf4QIod";
    private static final String PROJECT_ID = "7c55d8e5238d42e49fd9ce11b24b035b";
    private static final String REGION = "cn-north-7";
    private static final String KEYID = "c1f52e49-8e5c-4772-8713-ead33ed9faa2";



    @Test
    public void Should_ok_When_LocalGenerate() throws NoSuchAlgorithmException {
        DataKeyGenerate dataKeyGenerate = DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.LOCAL_GENERATE);
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyGenerate.dataKeyGenerate(huaweiConfig, dataKeyMaterials);
        System.out.println(Base64.getEncoder().encodeToString(dataKeyMaterials.getPlaintextDataKey().getEncoded()));
    }


    @Test(expected = HuaweicloudException.class)
    public void Should_ok_When_KMSGenerate() throws NoSuchAlgorithmException {
        DataKeyGenerate dataKeyGenerate = DataKeyGenerateFactory.getDataKeyGenerate(DataKeyGenerateType.KMS_GENERATE);
        HuaweiConfig huaweiConfig = HuaweiConfig.builder()
                .buildSk(SECRET_ACCESS_KEY)
                .buildAk(ACCESS_KEY)
                .buildKmsConfig(Collections.singletonList(new KMSConfig(REGION, KEYID, PROJECT_ID)))
                .buildCryptoAlgorithm(CryptoAlgorithm.AES_256_GCM_NOPADDING)
                .build();
        DataKeyMaterials dataKeyMaterials = new DataKeyMaterials();
        dataKeyGenerate.dataKeyGenerate(huaweiConfig, dataKeyMaterials);
        System.out.println(Base64.getEncoder().encodeToString(dataKeyMaterials.getPlaintextDataKey().getEncoded()));
    }
}
