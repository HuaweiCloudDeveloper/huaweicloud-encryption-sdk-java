package com.huaweicloud.encryptionsdk.cache;

import com.huaweicloud.encryptionsdk.model.DataKeyMaterials;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.TreeSet;

/**
 * @description: 本地缓存
 */
public class LocalDataKeyCache implements DataKeyCache {

    /**
     * 数据密钥缓存容量
     */
    private static final int DEFAULT_CAPACITY = 1 << 4;

    /**
     * 默认数据密钥缓存存活时间
     */
    private static final int DEFAULT_TTL = 1000000;

    /**
     * 数据密钥缓存容量，即{cache}最大存入数据密钥缓存个数
     */
    private int capacity;

    /**
     * 数据密钥缓存存活时间
     */
    private long keyExpireTime;

    /**
     * accessOrder为true时，访问和插入都会把元素置位队列尾部，用于实现LRU
     * 最新访问的数据将放在队列尾部
     */
    private final LinkedHashMap<String, BaseEntry> cache = new LinkedHashMap<>(DEFAULT_CAPACITY, 0.75f, true);

    /**
     * treeSet对缓存进行存活时间排序存储，用于淘汰过期缓存
     */
    private final TreeSet<BaseEntry> treeSet = new TreeSet<>();

    public LocalDataKeyCache() {
        this.capacity = DEFAULT_CAPACITY;
        this.keyExpireTime = DEFAULT_TTL;
    }

    public void setCapacity(int capacity) {
        this.capacity = capacity;
    }

    @Override
    public EncryptCacheEntry getEntryForEncrypt(String cacheId, UsageStatus usageStatus) {
        BaseEntry entry = getEntry(cacheId);
        if (entry == null) {
            return null;
        }
        if (entry.isExpired()) {
            entry.expired();
            return null;
        }
        UsageStatus status = entry.addUsageInfo(usageStatus);
        return new EncryptionEntryExposed(entry, status);
    }

    @Override
    public void putEntryForEncrypt(String cacheId, DataKeyMaterials dataKeyMaterials, UsageStatus initialUsage) {
        BaseEntry baseEntry = new BaseEntry(cacheId, keyExpireTime + System.currentTimeMillis(), dataKeyMaterials,
            initialUsage);
        putEntry(baseEntry);
    }

    @Override
    public void putEntryForEncrypt(String cacheId, long surviveTime, DataKeyMaterials dataKeyMaterials,
        UsageStatus initialUsage) {
        BaseEntry baseEntry = new BaseEntry(cacheId, surviveTime + System.currentTimeMillis(), dataKeyMaterials,
            initialUsage);
        putEntry(baseEntry);
    }

    @Override
    public DecryptCacheEntry getEntryForDecrypt(String cacheId) {
        BaseEntry entry = getEntry(cacheId);
        if (entry == null) {
            return null;
        }
        if (entry.isExpired()) {
            entry.expired();
            return null;
        }
        return (DecryptCacheEntry) entry;
    }

    @Override
    public void putEntryForDecrypt(String cacheId, long surviveTime, DataKeyMaterials dataKeyMaterials) {
        putEntry(new DecryptionEntry(cacheId, surviveTime + System.currentTimeMillis(), dataKeyMaterials, null));
    }

    @Override
    public void putEntryForDecrypt(String cacheId, DataKeyMaterials dataKeyMaterials) {
        putEntry(new DecryptionEntry(cacheId, keyExpireTime + System.currentTimeMillis(), dataKeyMaterials, null));
    }

    @Override
    public void setSurvivalTime(long survivalTime) {
        this.keyExpireTime = survivalTime;
    }

    /**
     * 缓存value基类，封装了缓存数据的过期时间，使用情况，实际数据等
     */
    private class BaseEntry implements Comparable<BaseEntry> {
        private String key;

        private long expireTimeStamp;

        private long createTimeStamp = System.currentTimeMillis();

        private DataKeyMaterials material;

        private UsageStatus usageStatus;

        private BaseEntry(String key, long expireTime, DataKeyMaterials material, UsageStatus usageStatus) {
            this(key, expireTime);
            this.material = material;
            this.usageStatus = usageStatus;
        }

        /**
         * @return com.huaweicloud.encryptionsdk.cache.DataKeyCache.UsageStatus
         * @Description ：累加使用情况
         * @Param [usageStatus]
         **/
        public synchronized UsageStatus addUsageInfo(UsageStatus usageStatus) {
            this.usageStatus = this.usageStatus.add(usageStatus);
            return this.usageStatus;
        }

        private BaseEntry(String key, long expireTimeStamp) {
            this.key = key;
            this.expireTimeStamp = expireTimeStamp;
        }

        public String getKey() {
            return key;
        }

        boolean isExpired() {
            return System.currentTimeMillis() > expireTimeStamp;
        }

        /**
         * @return void
         * @Description ：删除过期缓存
         * @Param []
         **/
        void expired() {
            removeEntry(this);
        }

        @Override
        public int compareTo(BaseEntry o) {
            int num = Long.compare(this.expireTimeStamp, o.expireTimeStamp);
            return num == 0 ? Long.compare(this.createTimeStamp, o.createTimeStamp) : num;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            BaseEntry baseEntry = (BaseEntry) o;
            return expireTimeStamp == baseEntry.expireTimeStamp && createTimeStamp == baseEntry.createTimeStamp
                && Objects.equals(key, baseEntry.key) && Objects.equals(material, baseEntry.material) && Objects.equals(
                usageStatus, baseEntry.usageStatus);
        }

        @Override
        public int hashCode() {
            return Objects.hash(key, expireTimeStamp, createTimeStamp, material, usageStatus);
        }
    }

    /**
     * BaseEntry和usageStatus外部封装，用于加密数据密钥获取的的返回
     * 防止多线程情况下，多个线程同时拿到BaseEntry后，进行使用情况新增后，本来单个线程使用量未超过限制，但是由于多个线程新增后，
     * 导致缓存使用量超过限制，所有线程都无法再使用该缓存
     */
    private class EncryptionEntryExposed implements EncryptCacheEntry {
        private BaseEntry entry;

        private UsageStatus usageStatus;

        private EncryptionEntryExposed(BaseEntry entry, UsageStatus usageStatus) {
            this.entry = entry;
            this.usageStatus = usageStatus;
        }

        @Override
        public UsageStatus getUsageStatus() {
            return usageStatus;
        }

        @Override
        public DataKeyMaterials getDataKeyMaterials() {
            return entry.material;
        }

        @Override
        public void invalidate() {
            removeEntry(entry);
        }
    }

    /**
     * BaseEntry外部封装，用于加密数据密钥获取的的返回
     * 区别于{EncryptionEntryExposed}
     */
    private class DecryptionEntry extends BaseEntry implements DecryptCacheEntry {

        private DecryptionEntry(String key, long expireTime, DataKeyMaterials material, UsageStatus usageStatus) {
            super(key, expireTime, material, usageStatus);
        }

        @Override
        public DataKeyMaterials getDataKeyMaterials() {
            return super.material;
        }

        @Override
        public void invalidate() {
            removeEntry(this);
        }
    }

    private synchronized void removeEntry(BaseEntry entry) {
        cache.remove(entry.key, entry);
        treeSet.remove(entry);
    }

    private synchronized BaseEntry getEntry(String key) {
        BaseEntry entry = cache.get(key);
        return entry;
    }

    private synchronized void putEntry(BaseEntry entry) {
        BaseEntry oldEntry = cache.put(entry.key, entry);
        if (oldEntry != null) {
            removeEntry(oldEntry);
        }
        treeSet.add(entry);
        // 淘汰过期条目
        while (!treeSet.isEmpty() && treeSet.first().expireTimeStamp < System.currentTimeMillis()) {
            removeEntry(treeSet.first());
        }
        // 检查是否超出上限
        checkCapacity();
    }

    /**
     * @return void
     * @Description ：存入缓存前，检查容量是否还有剩余，超出容量则删除存活时间最短的缓存
     * @Param []
     **/
    private void checkCapacity() {
        while (cache.size() > capacity) {
            Iterator<BaseEntry> iterator = cache.values().iterator();
            removeEntry(iterator.next());
        }
    }

}
