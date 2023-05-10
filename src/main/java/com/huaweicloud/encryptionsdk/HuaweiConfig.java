package com.huaweicloud.encryptionsdk;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.KMSConfig;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;

import java.util.List;

public class HuaweiConfig {

    private String ak;

    private String sk;

    /**
     * 是否开启自寻region KeyRing
     */
    private boolean isDiscovery;

    private List<KMSConfig> kmsConfigList;

    private CryptoAlgorithm cryptoAlgorithm;

    public String getAk() {
        return ak;
    }

    public String getSk() {
        return sk;
    }

    public boolean isDiscovery() {
        return isDiscovery;
    }

    public List<KMSConfig> getKmsConfigList() {
        return kmsConfigList;
    }

    public void setKmsConfigList(List<KMSConfig> kmsConfigList) {
        this.kmsConfigList = kmsConfigList;
    }

    public CryptoAlgorithm getCryptoAlgorithm() {
        return cryptoAlgorithm;
    }


    public void setCryptoAlgorithm(CryptoAlgorithm cryptoAlgorithm) {
        this.cryptoAlgorithm = cryptoAlgorithm;
    }

    public static HuaweiConfigBuilder builder() {
        return new HuaweiConfigBuilder();
    }


    public static class HuaweiConfigBuilder {

        private final HuaweiConfig huaweiConfig = new HuaweiConfig();


        public HuaweiConfigBuilder buildCryptoAlgorithm(CryptoAlgorithm cryptoAlgorithm) {
            huaweiConfig.cryptoAlgorithm = cryptoAlgorithm;
            return this;
        }


        public HuaweiConfigBuilder buildKmsConfig(List<KMSConfig> kmsConfigList) {
            huaweiConfig.kmsConfigList = kmsConfigList;
            return this;
        }

        public HuaweiConfigBuilder buildAk(String ak) {
            if (Utils.isEmpty(ak)) {
                throw new HuaweicloudException(ErrorMessage.AK_NULL_EXCEPTION.getMessage());
            }
            huaweiConfig.ak = ak;
            return this;
        }

        public HuaweiConfigBuilder buildSk(String sk) {
            if (Utils.isEmpty(sk)) {
                throw new HuaweicloudException(ErrorMessage.SK_NULL_EXCEPTION.getMessage());
            }
            huaweiConfig.sk = sk;
            return this;
        }

        public HuaweiConfigBuilder buildDiscovery(boolean isDiscovery) {
            huaweiConfig.isDiscovery = isDiscovery;
            return this;
        }


        public HuaweiConfig build() {
            return huaweiConfig;
        }

    }


}
