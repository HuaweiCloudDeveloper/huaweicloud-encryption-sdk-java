package com.huaweicloud.encryptionsdk.model.enums;

/**
 * @description: 主密钥提供者
 */
public enum KeyProviderEnum {
    LOCAL_PROVIDER(1, "huawei-local"),
    KMS_PROVIDER(2, "huawei-kms");
    private int code;
    private String name;

    KeyProviderEnum(int code, String name) {
        this.code = code;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
