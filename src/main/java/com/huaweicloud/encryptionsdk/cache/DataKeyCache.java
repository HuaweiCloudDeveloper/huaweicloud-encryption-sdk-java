package com.huaweicloud.encryptionsdk.cache;

import com.huaweicloud.encryptionsdk.common.Utils;
import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;

public interface DataKeyCache {

    /**
     * @return com.huaweicloud.encryptionsdk.cache.DataKeyCache.EncryptCacheEntry
     * @Description : 该方法用于从缓存中获取加密数据的数据密钥
     * @Param [cacheId, usageStatus]
     * cacheId: 缓存的key，使用算法类型，加密上下文等加密必要信息通过摘要算法生成
     * usageStatus: 本次数据密钥使用情况，包括数据密钥需要加密数据长度等
     **/
    EncryptCacheEntry getEntryForEncrypt(String cacheId, UsageStatus usageStatus);

    /**
     * @return void
     * @Description ：存储加密数据密钥到缓存
     * @Param [cacheId, dataKeyMaterials, initialUsage]
     * cacheId: 缓存的key
     * dataKeyMaterials: 数据密钥材料，缓存value的实际内容
     * initialUsage: 数据密钥使用情况初始化对象
     **/
    void putEntryForEncrypt(String cacheId, DataKeyMaterials dataKeyMaterials, UsageStatus initialUsage);

    /**
     * @return void
     * @Description ：存储加密数据密钥到缓存，可单独设置存活时间
     * @Param [cacheId, surviveTime, dataKeyMaterials, initialUsage]
     * cacheId：缓存的key
     * surviveTime：密钥存活时间，单独设置的存活时间会覆盖默认的存活时间
     * dataKeyMaterials: 数据密钥材料，缓存value的实际内容
     * initialUsage: 数据密钥使用情况初始化对象
     **/
    void putEntryForEncrypt(String cacheId, long surviveTime, DataKeyMaterials dataKeyMaterials,
        UsageStatus initialUsage);

    /**
     * @return com.huaweicloud.encryptionsdk.cache.DataKeyCache.DecryptCacheEntry
     * @Description ：获取缓存的数据解密密钥
     * @Param [cacheId]
     * cacheId：
     **/
    DecryptCacheEntry getEntryForDecrypt(String cacheId);

    /**
     * @return void
     * @Description ：存储解密数据密钥到缓存，可单独设置存活时间
     * @Param [cacheId, surviveTime, dataKeyMaterials]
     * cacheId：缓存的key
     * surviveTime：密钥存活时间，单独设置的存活时间会覆盖默认的存活时间
     * dataKeyMaterials: 数据密钥材料，缓存value的实际内容
     **/
    void putEntryForDecrypt(String cacheId, long surviveTime, DataKeyMaterials dataKeyMaterials);

    /**
     * @return void
     * @Description ：存储解密数据密钥到缓存
     * @Param [cacheId, decryptionMaterials]
     * cacheId: 缓存的key
     * dataKeyMaterials: 数据密钥材料，缓存value的实际内容
     **/
    void putEntryForDecrypt(String cacheId, DataKeyMaterials decryptionMaterials);

    /**
     * @return void
     * @Description ：设置缓存统一最大存活时间
     * @Param [survivalTime]
     * survivalTime：缓存最大存活时间
     **/
    void setSurvivalTime(long survivalTime);

    /**
     * 加密密钥缓存同意操作接口
     */
    interface EncryptCacheEntry {

        UsageStatus getUsageStatus();

        /**
         * @return com.huaweicloud.encryptionsdk.model.DataKeyMaterials
         * @Description ：从缓存中的value的封装对象BaseEntry中获取到实际的数据密钥相关信息
         **/
        DataKeyMaterials getDataKeyMaterials();

        /**
         * @return void
         * @Description ：手动销毁无效缓存，将使用者对象从缓存中删除
         **/
        default void invalidate() {
        }
    }

    /**
     * 解密密钥缓存同意操作接口
     */
    interface DecryptCacheEntry {

        /**
         * @return com.huaweicloud.encryptionsdk.model.DataKeyMaterials
         * @Description ：从缓存中的value的封装对象BaseEntry中获取到实际的数据密钥相关信息
         **/
        DataKeyMaterials getDataKeyMaterials();

        default void invalidate() {
        }
    }

    /**
     * 加密密钥使用情况封装类
     */
    class UsageStatus {

        /**
         * 加密密钥本次需要加密或者已加密字节总数
         */
        private long bytesEncryptCount;

        /**
         * 加密密钥使用次数
         */
        private long messageEncryptCount;

        public UsageStatus(long bytesEncryptCount, long messageEncryptCount) {
            this.bytesEncryptCount = bytesEncryptCount;
            this.messageEncryptCount = messageEncryptCount;
        }

        public long getBytesEncryptCount() {
            return bytesEncryptCount;
        }

        public long getMessageEncryptCount() {
            return messageEncryptCount;
        }

        /**
         * @return com.huaweicloud.encryptionsdk.cache.DataKeyCache.UsageStatus
         * @Description ：在原有的使用情况下，累加当次密钥使用情况，返回新的总数封装
         * @Param [usageStatus]
         * usageStatus ： 当次加密所使用的次数和字节数量封装
         **/
        public UsageStatus add(UsageStatus usageStatus) {
            return new UsageStatus(Utils.addPreventOverFlow(bytesEncryptCount, usageStatus.bytesEncryptCount),
                Utils.addPreventOverFlow(messageEncryptCount, usageStatus.messageEncryptCount));
        }

    }

}
