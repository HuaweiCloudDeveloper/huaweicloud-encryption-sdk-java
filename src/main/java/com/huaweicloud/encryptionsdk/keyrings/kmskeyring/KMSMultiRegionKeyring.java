package com.huaweicloud.encryptionsdk.keyrings.kmskeyring;

import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;

/**
 * @description: kms实现keiring
 */
public class KMSMultiRegionKeyring extends KMSKeyring {

    @Override
    public void doDecrypt(DataKeyMaterials dataKeyMaterials) {
        super.realDecrypt(dataKeyMaterials);
    }
}
