package com.huaweicloud.encryptionsdk.keyrings;

import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.KeyringNotFoundException;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawAesKeyring;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawKeyring;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawRSAKeyring;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawSM2Keyring;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawSM4CBCKeyring;
import com.huaweicloud.encryptionsdk.keyrings.rawkeyring.RawSM4Keyring;
import com.huaweicloud.encryptionsdk.model.enums.KeyringTypeEnum;

/**
 * @description: RawKeyring工厂
 */
public class RawKeyringFactory implements KeyringFactory {
    @Override
    public RawKeyring getKeyring(String type) {
        KeyringTypeEnum keyringTypeEnum = KeyringTypeEnum.getRawKeyringType(type);
        if (keyringTypeEnum == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NOT_FOUND_EXCEPTION.getMessage());
        }
        switch (keyringTypeEnum) {
            case RAW_AES:
                return new RawAesKeyring();
            case RAW_RSA:
                return new RawRSAKeyring();
            case RAW_SM2:
                return new RawSM2Keyring();
            case RAW_SM4_GCN:
                return new RawSM4Keyring();
            case RAW_SM4_CBC:
                return new RawSM4CBCKeyring();
            default:
                return null;
        }
    }

}
