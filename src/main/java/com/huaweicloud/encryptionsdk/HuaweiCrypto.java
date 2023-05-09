package com.huaweicloud.encryptionsdk;


import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.exception.KeyringNotFoundException;
import com.huaweicloud.encryptionsdk.handler.CryptoHadler;
import com.huaweicloud.encryptionsdk.handler.DefaultCryptoHandler;
import com.huaweicloud.encryptionsdk.keyrings.Keyring;
import com.huaweicloud.encryptionsdk.keyrings.kmskeyring.KMSKeyring;
import com.huaweicloud.encryptionsdk.meterialmanager.CacheCryptoMeterialManager;
import com.huaweicloud.encryptionsdk.meterialmanager.CryptoMeterialManager;
import com.huaweicloud.encryptionsdk.meterialmanager.DefaultCryptoMeterialsManager;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;
import com.huaweicloud.encryptionsdk.model.CryptoResult;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import com.huaweicloud.encryptionsdk.model.request.EncryptRequest;
import org.apache.commons.codec.DecoderException;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Map;

public class HuaweiCrypto {

    private CryptoHadler cryptoHandler;

    private HuaweiConfig huaweiConfig;

    private CryptoMeterialManager cryptoMeterialManager;

    private Keyring keyring;

    public HuaweiCrypto(HuaweiConfig huaweiConfig) {
        this.huaweiConfig = huaweiConfig;
        huaweiConfig.setCryptoAlgorithm(huaweiConfig.getCryptoAlgorithm() == null ? CryptoAlgorithm.AES_128_GCM_NOPADDING : huaweiConfig.getCryptoAlgorithm());
        this.cryptoHandler = new DefaultCryptoHandler();
        this.cryptoMeterialManager = new DefaultCryptoMeterialsManager(huaweiConfig);
    }

    public HuaweiCrypto withCryptoMeterialManager(CryptoMeterialManager cryptoMeterialManager) {
        this.cryptoMeterialManager = cryptoMeterialManager;
        return this;
    }

    public HuaweiCrypto withKeyring(Keyring keyring) {
        this.keyring = keyring;
        if (keyring instanceof KMSKeyring) {
            ((KMSKeyring) keyring).setHuaweiConfig(huaweiConfig);
        }
        return this;
    }

    public CryptoResult<byte[]> encrypt(byte[] plaintText) throws NoSuchAlgorithmException, IOException, DecoderException {
        return encrypt(new EncryptRequest(Collections.emptyMap(), plaintText));
    }

    public CryptoResult<byte[]> encrypt(EncryptRequest request) {
        if (keyring == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.getMessage());
        }

        DataKeyMaterials dataKeyMaterials = null;
        try {
            dataKeyMaterials = new DataKeyMaterials();
            dataKeyMaterials.setEncryptionContexts(request.getEncryptionContext());
            dataKeyMaterials.setCryptoAlgorithm(huaweiConfig.getCryptoAlgorithm());
            if (cryptoMeterialManager instanceof CacheCryptoMeterialManager && ((CacheCryptoMeterialManager) cryptoMeterialManager).getMaxByteLimit() < request.getPlainText().length) {
                throw new HuaweicloudException(ErrorMessage.DATA_EXCEED_LIMIT.getMessage());
            }
            dataKeyMaterials = cryptoMeterialManager.getMaterialsForEncrypt(keyring, dataKeyMaterials, request.getPlainText().length);
            return cryptoHandler.encrypt(request, dataKeyMaterials);
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.CIPHER_EXCEPTION.getMessage(), e);

        }
    }


    public CryptoResult<byte[]> decrypt(byte[] cipherText) {
        if (keyring == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.getMessage());
        }

        DataKeyMaterials dataKeyMaterials = null;
        try {
            dataKeyMaterials = cryptoMeterialManager.getMaterialsForDecrypt(keyring, cipherText);
            return cryptoHandler.decrypt(cipherText, dataKeyMaterials);
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.DECRYPT_EXCEPTION.getMessage(), e);
        }
    }


    public CryptoResult<OutputStream> encrypt(InputStream inputStream, OutputStream outputStream, Map<String, String> encryptionContext) {
        if (keyring == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.getMessage());
        }

        DataKeyMaterials dataKeyMaterials = null;
        try {
            dataKeyMaterials = new DataKeyMaterials();
            dataKeyMaterials.setEncryptionContexts(encryptionContext == null ? Collections.emptyMap() : encryptionContext);
            dataKeyMaterials.setCryptoAlgorithm(huaweiConfig.getCryptoAlgorithm());
            if (cryptoMeterialManager instanceof CacheCryptoMeterialManager && ((CacheCryptoMeterialManager) cryptoMeterialManager).getMaxByteLimit() < inputStream.available()) {
                throw new HuaweicloudException(ErrorMessage.DATA_EXCEED_LIMIT.getMessage());
            }
            dataKeyMaterials = cryptoMeterialManager.getMaterialsForEncrypt(keyring, dataKeyMaterials, inputStream.available());
            return cryptoHandler.encrypt(inputStream, outputStream, dataKeyMaterials, encryptionContext);
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.CIPHER_EXCEPTION.getMessage(), e);
        }
    }


    public CryptoResult<OutputStream> decrypt(InputStream inputStream, OutputStream outputStream) {
        if (keyring == null) {
            throw new KeyringNotFoundException(ErrorMessage.KEYRING_NULL_EXCEPTION.getMessage());
        }
        DataKeyMaterials dataKeyMaterials = null;
        try {
            dataKeyMaterials = cryptoMeterialManager.getMaterialsForStreamDecrypt(keyring, inputStream);
            return cryptoHandler.decrypt(inputStream, outputStream, dataKeyMaterials);
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.DECRYPT_EXCEPTION.getMessage(), e);
        }
    }


}
