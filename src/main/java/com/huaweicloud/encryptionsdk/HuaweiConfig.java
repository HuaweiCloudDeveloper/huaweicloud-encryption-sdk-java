package com.huaweicloud.encryptionsdk;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class HuaweiConfig {

    private String ak;

    private String sk;

    /**
     * 是否开启自寻region KeyRing
     */
    private boolean isDiscovery;

    private List<KMSConfig> kmsConfigList;

    private CryptoAlgorithm cryptoAlgorithm;

    public void setAk(String ak) {
        if (Utils.isEmpty(ak)) {
            throw new HuaweicloudException(ErrorMessage.AK_NULL_EXCEPTION.getMessage());
        }
        this.ak = ak;
    }

    public void setSk(String sk) {
        if (Utils.isEmpty(sk)) {
            throw new HuaweicloudException(ErrorMessage.AK_NULL_EXCEPTION.getMessage());
        }
        this.sk = sk;
    }
}
