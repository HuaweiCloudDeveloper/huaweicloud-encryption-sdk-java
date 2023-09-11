package com.huaweicloud.encryptionsdk.keyrings.kmskeyring;

import com.huaweicloud.encryptionsdk.HuaweiConfig;
import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.KMSConfig;

import java.util.ArrayList;
import java.util.List;

/**
 * @description: kms密钥环，无需用户输入keyId，region等信息
 */
public class KMSDiscoveryKeyring extends KMSKeyring {

    @Override
    public void doDecrypt(DataKeyMaterials dataKeyMaterials) {
        prepareKeyId(dataKeyMaterials);
        super.realDecrypt(dataKeyMaterials);
    }

    private void prepareKeyId(DataKeyMaterials dataKeyMaterials) {
        List<KMSConfig> kmsConfigList = new ArrayList<>();
        for (CiphertextDataKey ciphertextDataKey : dataKeyMaterials.getCiphertextDataKeys()) {
            if (!checkDisvocery(ciphertextDataKey)) {
                throw new HuaweicloudException(ErrorMessage.NOT_SUPPORT_DISCOVERY_DECRYPT.getMessage());
            }
            kmsConfigList.add(new KMSConfig(ciphertextDataKey.getRegion(), ciphertextDataKey.getKeyId(),
                ciphertextDataKey.getProjectId(), ciphertextDataKey.getEndPoint()));
        }
        HuaweiConfig huaweiConfig = super.getHuaweiConfig();
        huaweiConfig.setKmsConfigList(kmsConfigList);
    }

    private boolean checkDisvocery(CiphertextDataKey ciphertextDataKey) {
        return ciphertextDataKey.isDiscovery() && !Utils.isEmpty(ciphertextDataKey.getKeyId()) && !Utils.isEmpty(
            ciphertextDataKey.getRegion()) && !Utils.isEmpty(ciphertextDataKey.getProjectId());
    }
}
