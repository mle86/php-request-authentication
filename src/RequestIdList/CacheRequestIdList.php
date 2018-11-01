<?php

namespace mle86\RequestAuthentication\RequestIdList;

use mle86\RequestAuthentication\Exception\DuplicateRequestIDException;
use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use Psr\SimpleCache\CacheInterface;

/**
 * Cache Request ID List.
 *
 * Stores previously-seen Request IDs
 * in a PSR-16 cache.
 *
 * The constructor requires setting a key prefix for the entries
 * to avoid cluttering the cache's key namespace
 * with unpredictable entries.
 *
 * The constructor supports setting a TTL for the entries.
 */
class CacheRequestIdList implements RequestIdList
{

    private $cache;
    private $keyPrefix;
    private $ttl;
    private $hashAlgo = 'sha256';

    /**
     * @param CacheInterface $psr16cache  The cache to use.
     * @param string $cacheKeyPrefix      The cache key prefix to use.
     * @param int|\DateInterval|null $ttl The TTL to use (in seconds or as a DateInterval). Without this, the entries won't have a TTL at all!
     */
    public function __construct(CacheInterface $psr16cache, string $cacheKeyPrefix, $ttl = null)
    {
        if ($cacheKeyPrefix === '') {
            throw new InvalidArgumentException('keyPrefix cannot be empty');
        }
        if (!(is_int($ttl) || $ttl instanceof \DateInterval || $ttl === null)) {
            throw new InvalidArgumentException('ttl must be int|DateInterval|null');
        }
        if ($ttl < 0 || $ttl === 0) {
            throw new InvalidArgumentException('ttl must be positive or null');
        }

        $this->cache     = $psr16cache;
        $this->keyPrefix = $cacheKeyPrefix;
        $this->ttl       = $ttl;
    }

    public function contains(string $requestId): bool
    {
        return $this->cache->has($this->cacheKey($requestId));
    }

    public function put(string $requestId): void
    {
        $cacheKey = $this->cacheKey($requestId);

        if ($this->cache->has($cacheKey)) {
            throw new DuplicateRequestIDException("duplicate request id: '{$requestId}'");
        }

        $this->cache->set($cacheKey, 1, $this->ttl);
    }

    private function cacheKey(string $requestId): string
    {
        // There's no guarantees about the request id
        // so we'd better hash it to avoid invalid cache keys.
        return $this->keyPrefix . hash($this->hashAlgo, $requestId);
    }

}
