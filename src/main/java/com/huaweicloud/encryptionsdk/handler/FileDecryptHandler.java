package com.huaweicloud.encryptionsdk.handler;

import com.huaweicloud.encryptionsdk.exception.ErrorMessage;
import com.huaweicloud.encryptionsdk.exception.HuaweicloudException;
import com.huaweicloud.encryptionsdk.model.CipherHeader;
import com.huaweicloud.encryptionsdk.model.enums.CryptoAlgorithm;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Map;

/**
 * @description: 文件解密处理器
 */
public class FileDecryptHandler {

    private int mode;

    private CryptoAlgorithm algorithm;

    private SecretKey secretKey;

    /**
     * 未解析的byte数组
     */
    private byte[] unParsedByte;

    private CipherHeader header;

    public FileDecryptHandler(CryptoAlgorithm algorithm, SecretKey secretKey, int mode) {
        this.mode = mode;
        this.algorithm = algorithm;
        this.secretKey = secretKey;
        this.unParsedByte = new byte[0];
    }

    /**
     * @return void
     * @Description ：数据流解密操作
     * 由于每次读取密文长度固定为blockSize，该数据块长度不一定是实际密文长度，
     * 可能会超过当前解密长度，也可能短于实际解密所需长度，故需对长度进行处理。
     * 使用unParsedByte对多余的字节进行临时保存，等下次循环解密时再进行数据拼接
     * cipherHeader中存储了当前加密文段的iv和密文长度，密文长度根据存储的contentLength确定
     * @Param [inputStream, outputStream, encryptionContext, blockSize]
     * inputStream：密文输入流
     * outputStream：明文输出流
     * encryptionContext：加密上下文
     * blockSize：每次读取流中数据块大小
     **/
    public void processByte(InputStream inputStream, OutputStream outputStream, Map<String, String> encryptionContext,
        int blockSize) throws IOException {
        try {
            byte[] readBytes = new byte[blockSize];
            int readLen = 0;
            CipherHandler cipherHandler = new CipherHandler(algorithm, secretKey, mode);
            while ((readLen = inputStream.read(readBytes)) != -1) {
                int unParsedByteTotal = readLen + unParsedByte.length;
                byte[] bytesToParse = new byte[unParsedByteTotal];
                System.arraycopy(unParsedByte, 0, bytesToParse, 0, unParsedByte.length);
                System.arraycopy(readBytes, 0, bytesToParse, unParsedByte.length, readLen);
                byte[] cipherText = null;
                if (header != null) {
                    if (header.getContentLength() > unParsedByteTotal) {
                        unParsedByte = bytesToParse;
                        continue;
                    }
                    cipherText = Arrays.copyOfRange(bytesToParse, 0, header.getContentLength());
                    if (header.getContentLength() <= unParsedByteTotal) {
                        unParsedByte = Arrays.copyOfRange(bytesToParse, header.getContentLength(), bytesToParse.length);
                    }
                } else {
                    CipherHeader cipherHeader = new CipherHeader();
                    int fileHeaderLength = cipherHeader.getFileHeaderLength(algorithm);
                    byte[] headerBytes = Arrays.copyOfRange(bytesToParse, 0, fileHeaderLength);
                    cipherHeader.deserializeFileFields(headerBytes, algorithm);
                    // 加密数据的密文数据大于剩余字节总数，则进行下一轮读取
                    this.header = cipherHeader;
                    if (cipherHeader.getContentLength() > unParsedByteTotal - fileHeaderLength) {
                        unParsedByte = Arrays.copyOfRange(bytesToParse, fileHeaderLength, unParsedByteTotal);
                        continue;
                    }
                    cipherText = Arrays.copyOfRange(bytesToParse, fileHeaderLength,
                        fileHeaderLength + cipherHeader.getContentLength());
                    if (cipherHeader.getContentLength() <= unParsedByteTotal - cipherHeader.getFileHeaderLength(
                        algorithm)) {
                        unParsedByte = Arrays.copyOfRange(bytesToParse,
                            cipherHeader.getContentLength() + fileHeaderLength, bytesToParse.length);
                    }
                }
                cipherHandler.setIv(this.header.getIv());
                cipherHandler.processDecryptByte(cipherText, cipherText.length, outputStream, encryptionContext);
                header = null;
            }
            // unParsedByte 不为空，则需进行继续解密知道解密结束
            while (unParsedByte != null && unParsedByte.length > 0) {
                if (this.header == null) {
                    CipherHeader cipherHeader = new CipherHeader();
                    int fileHeaderLength = cipherHeader.getFileHeaderLength(algorithm);
                    byte[] headerBytes = Arrays.copyOfRange(unParsedByte, 0, fileHeaderLength);
                    cipherHeader.deserializeFileFields(headerBytes, algorithm);
                    // 加密数据的密文数据大于剩余字节总数，则进行下一轮读取
                    this.header = cipherHeader;
                    unParsedByte = Arrays.copyOfRange(unParsedByte, fileHeaderLength, unParsedByte.length);
                }
                byte[] cipherText = Arrays.copyOfRange(unParsedByte, 0, this.header.getContentLength());
                cipherHandler.setIv(this.header.getIv());
                cipherHandler.processDecryptByte(cipherText, cipherText.length, outputStream, encryptionContext);
                unParsedByte = Arrays.copyOfRange(unParsedByte, this.header.getContentLength(), unParsedByte.length);
                header = null;
            }
        } catch (Exception e) {
            throw new HuaweicloudException(ErrorMessage.FILE_CHANGED_ERROR.getMessage());
        }

    }

}
