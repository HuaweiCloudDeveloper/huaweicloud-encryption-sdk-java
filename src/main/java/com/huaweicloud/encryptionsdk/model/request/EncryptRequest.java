package com.huaweicloud.encryptionsdk.model.request;

import java.util.HashMap;
import java.util.Map;

public class EncryptRequest {
    private Map<String, String> encryptionContext;

    private byte[] plainText;

    public EncryptRequest(Map<String, String> encryptionContext, byte[] plainText) {
        this.encryptionContext = encryptionContext == null ? new HashMap<>() : encryptionContext;
        this.plainText = plainText;
    }

    public Map<String, String> getEncryptionContext() {
        return encryptionContext;
    }

    public void setEncryptionContext(Map<String, String> encryptionContext) {
        this.encryptionContext = encryptionContext;
    }

    public byte[] getPlainText() {
        return plainText;
    }

    public void setPlainText(byte[] plainText) {
        this.plainText = plainText;
    }
}
