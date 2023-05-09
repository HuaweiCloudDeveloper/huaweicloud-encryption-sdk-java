
package com.huaweicloud.encryptionsdk.keyrings;

import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;
import org.apache.commons.codec.DecoderException;

import java.io.IOException;
import java.util.concurrent.ExecutionException;


/**
 * Keyring is used to generate, encrypt and decrypt data keys.
 */
public interface Keyring {

    /**
     * Encrypt the given data key (if present) or generate one then encrypt
     *
     * @param dataKeyMaterials Data key materials needed for encryption.
     * @return Data key materials with encrypted data key added.
     */
    DataKeyMaterials encryptDataKey(DataKeyMaterials dataKeyMaterials) throws IOException, ExecutionException, InterruptedException, DecoderException;

    /**
     * Decrypt the cipher data keys
     *
     * @param dataKeyMaterials Data key materials needed for decryption.
     * @return Data key materials whit decrypted data key added.
     */
    DataKeyMaterials decryptDataKey(DataKeyMaterials dataKeyMaterials) throws IOException;

}
