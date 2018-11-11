# CacheRequestIdList Class

Cache Request ID List.

Stores previously-seen Request IDs
in a [PSR-16](https://www.php-fig.org/psr/psr-16/) cache

The constructor requires setting a key prefix for the entries
to avoid cluttering the cache's key namespace
with unpredictable entries.

The constructor supports setting a TTL for the entries.


## Class Details

* Full class name: <code>mle86\\RequestAuthentication\\RequestIdList\\<b>CacheRequestIdList</b></code>
* Class file: [src/RequestIdList/CacheRequestIdList.php](../src/RequestIdList/CacheRequestIdList.php)


## Constructor

* <code><b>\_\_construct</b> ([CacheInterface](https://github.com/php-fig/simple-cache/blob/master/src/CacheInterface.php) $psr16Cache, string $cacheKeyPrefix, int|DateInterval $ttl = null)</code>  
    * `$psr16cache`: The cache to use.
    * `$cacheKeyPrefix`: The cache key prefix to use. Must not be empty.
    * `$ttl`: The TTL to use (in seconds or as a DateInterval).
        Without this, the entries won't have a TTL at all!
