package com.huaweicloud.encryptionsdk.meterialmanager;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;

import java.security.NoSuchAlgorithmException;

public interface DataKeyGenerate {
    void dataKeyGenerate(HuaweiConfig huaweiConfig, DataKeyMaterials dataKeyMaterials) throws NoSuchAlgorithmException;
}
