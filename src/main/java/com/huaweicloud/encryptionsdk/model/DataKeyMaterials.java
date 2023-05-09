package com.huaweicloud.encryptionsdk.model;


import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;

import javax.crypto.SecretKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DataKeyMaterials {

    private SecretKey plaintextDataKey;
    private List<CiphertextDataKey> ciphertextDataKeys = new ArrayList<>();
    private Map<String, String> encryptionContexts = new HashMap<>();
    private CryptoAlgorithm cryptoAlgorithm;

    public SecretKey getPlaintextDataKey() {
        return plaintextDataKey;
    }

    public void setPlaintextDataKey(SecretKey plaintextDataKey) {
        this.plaintextDataKey = plaintextDataKey;
    }

    public List<CiphertextDataKey> getCiphertextDataKeys() {
        return ciphertextDataKeys;
    }

    public void setCiphertextDataKeys(List<CiphertextDataKey> ciphertextDataKeys) {
        this.ciphertextDataKeys = ciphertextDataKeys;
    }

    public Map<String, String> getEncryptionContexts() {
        return encryptionContexts;
    }

    public void setEncryptionContexts(Map<String, String> encryptionContexts) {
        this.encryptionContexts = encryptionContexts;
    }

    public CryptoAlgorithm getCryptoAlgorithm() {
        return cryptoAlgorithm;
    }

    public void setCryptoAlgorithm(CryptoAlgorithm cryptoAlgorithm) {
        this.cryptoAlgorithm = cryptoAlgorithm;
    }

}
