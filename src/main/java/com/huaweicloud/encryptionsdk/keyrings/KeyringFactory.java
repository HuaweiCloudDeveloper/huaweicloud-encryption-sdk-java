package com.huaweicloud.encryptionsdk.keyrings;

/**
 * @description: keyring工厂，定义获取keyring的接口
 */
public interface KeyringFactory<T extends Keyring> {
    T getKeyring(String type);
}
