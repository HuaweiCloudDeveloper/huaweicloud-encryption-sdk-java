package com.huaweicloud.encryptionsdk.keyrings.rawkeyring;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.exception.EncryptException;
import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.exception.KeyringNotMatchException;
import com.huaweicloud.encryptionsdk.keyrings.Keyring;
import com.huaweicloud.encryptionsdk.model.CiphertextDataKey;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

/**
 * @description: 本地加密算法实现基类
 */
public abstract class RawKeyring implements Keyring {

    private static final Logger LOGGER = LoggerFactory.getLogger(RawKeyring.class);

    /**
     * 非对称密钥私钥路径
     */
    private final List<byte[]> privateKey = new ArrayList<>();

    /**
     * 非对称密钥公钥路径
     */
    private final List<byte[]> publicKey = new ArrayList<>();

    /**
     * 对称密钥路径
     */
    private final List<byte[]> symmetricKey = new ArrayList<>();

    public List<byte[]> getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(byte[]... privateKey) {
        this.privateKey.addAll(Arrays.asList(privateKey));
    }

    public void setPrivateKey(List<byte[]> privateKey) {
        this.privateKey.addAll(privateKey);
    }

    public List<byte[]> getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[]... publicKey) {
        this.publicKey.addAll(Arrays.asList(publicKey));
    }

    public void setPublicKey(List<byte[]> publicKey) {
        this.publicKey.addAll(publicKey);
    }

    public List<byte[]> getSymmetricKey() {
        return symmetricKey;
    }

    public void setSymmetricKey(byte[]... symmetricKey) {
        this.symmetricKey.addAll(Arrays.asList(symmetricKey));
    }

    public void setSymmetricKey(List<byte[]> symmetricKey) {
        this.symmetricKey.addAll(symmetricKey);
    }

    /**
     * @return java.util.List<byte [ ]>
     * @Description ：获取密钥环对应的解密主密钥
     * @Param []
     **/
    public abstract List<byte[]> getDecryptSecretKey() throws IOException;

    /**
     * @return java.util.List<byte [ ]>
     * @Description 获取密钥环对应的加密主密钥
     * @Param []
     **/
    public abstract List<byte[]> getEncryptSecretKey() throws IOException;

    /**
     * @return void
     * @Description ：本地密钥环加密数据密钥，有四种算法的实现子类定义处理逻辑
     * @Param [bytes, ciphertextDataKeys, dataKeyMaterials]
     * bytes：主密钥字节数组
     * ciphertextDataKeys：加密后数据密钥密文存储集合
     * dataKeyMaterials：加解密所需的相关必要信息
     **/
    public abstract void realEncrypt(byte[] bytes, List<CiphertextDataKey> ciphertextDataKeys,
        DataKeyMaterials dataKeyMaterials);

    /**
     * @return boolean
     * @Description ：本地密钥环解密数据密钥，有四种算法的实现子类定义处理逻辑
     * @Param [bytes, ciphertextDataKey, dataKeyMaterials]
     * bytes：主密钥字节数组
     * ciphertextDataKeys：数据密钥密文存储集合
     * dataKeyMaterials：加解密所需的相关必要信息
     **/
    public abstract boolean realDecrypt(byte[] bytes, CiphertextDataKey ciphertextDataKey,
        DataKeyMaterials dataKeyMaterials);

    @Override
    public DataKeyMaterials encryptDataKey(DataKeyMaterials dataKeyMaterials) throws IOException {
        List<byte[]> encryptSecretKey = getEncryptSecretKey();
        if (Utils.isEmpty(encryptSecretKey)) {
            throw new HuaweicloudException(ErrorMessage.MASTER_KEY_SHOULD_NOT_NULL.getMessage());
        }
        try {
            doEncrypt(dataKeyMaterials, encryptSecretKey);
        } catch (Exception e) {
            throw new EncryptException(ErrorMessage.ENCRYPT_EXCEPTION.getMessage(), e);
        }
        return dataKeyMaterials;
    }

    private void doEncrypt(DataKeyMaterials dataKeyMaterials, List<byte[]> masterSecretKey)
        throws ExecutionException, InterruptedException {
        List<CiphertextDataKey> ciphertextDataKeys = dataKeyMaterials.getCiphertextDataKeys();
        List<CompletableFuture<Void>> futureList = new ArrayList<>();
        for (byte[] bytes : masterSecretKey) {
            CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                try {
                    realEncrypt(bytes, ciphertextDataKeys, dataKeyMaterials);
                } catch (Exception e) {
                    LOGGER.warn(
                        "encrypt data key error by local master key,please check the server information is right");
                }
            });
            futureList.add(future);
        }
        CompletableFuture<Void> completableFuture = CompletableFuture.allOf(
            futureList.toArray(new CompletableFuture[0]));
        completableFuture.get();
        if (ciphertextDataKeys.size() <= 0) {
            throw new EncryptException(ErrorMessage.ENCRYPT_DATA_KEY_EXCEPTION.getMessage());
        }
        dataKeyMaterials.setCiphertextDataKeys(ciphertextDataKeys);
    }

    @Override
    public DataKeyMaterials decryptDataKey(DataKeyMaterials dataKeyMaterials) throws IOException {
        List<byte[]> encryptSecretKey = getDecryptSecretKey();
        if (Utils.isEmpty(encryptSecretKey)) {
            throw new HuaweicloudException(ErrorMessage.MASTER_KEY_SHOULD_NOT_NULL.getMessage());
        }
        doDecrypt(dataKeyMaterials, encryptSecretKey);
        if (Utils.isEmpty(dataKeyMaterials.getCiphertextDataKeys())) {
            throw new KeyringNotMatchException(ErrorMessage.KEYRING_NOT_MATCH_EXCEPTION.getMessage());
        }
        return dataKeyMaterials;
    }

    private void doDecrypt(DataKeyMaterials dataKeyMaterials, List<byte[]> masterSecretKey) {
        List<CiphertextDataKey> ciphertextDataKeys = dataKeyMaterials.getCiphertextDataKeys();
        for (byte[] bytes : masterSecretKey) {
            for (CiphertextDataKey ciphertextDataKey : ciphertextDataKeys) {
                boolean isDecrypted = realDecrypt(bytes, ciphertextDataKey, dataKeyMaterials);
                if (isDecrypted) {
                    return;
                }
            }
        }
        throw new KeyringNotMatchException(ErrorMessage.KEYRING_NOT_MATCH_EXCEPTION.getMessage());
    }

}
