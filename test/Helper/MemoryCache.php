<?php

namespace mle86\RequestAuthentication\Tests\Helper;

use Psr\SimpleCache\CacheInterface;

/**
 * Simple memory-backed PSR-16 CacheInterface implementation.
 * If the instance is destroyed, the cache contents are lost.
 *
 * @internal
 */
class MemoryCache implements CacheInterface
{

    private $cache = [];

    public function get($key, $default = null)
    {
        return ($this->has($key))
            ? $this->cache[$key][0]
            : $default;
    }

    public function set($key, $value, $ttl = null)
    {
        if ($ttl instanceof \DateInterval) {
            $expiration = (new \DateTime())->add($ttl);
            $ttl = $expiration->getTimestamp() - (new \DateTime())->getTimestamp();
        }
        if (is_int($ttl)) {
            $ttl += time();
        }

        $this->cache[$key] = [$value, $ttl];
    }

    public function delete($key)
    {
        unset($this->cache[$key]);
    }

    public function clear()
    {
        $this->cache = [];
    }

    public function getMultiple($keys, $default = null)
    {
        return array_map(
            function($key) use($default) { return $this->get($key, $default); },
            $keys);
    }

    public function setMultiple($values, $ttl = null)
    {
        foreach ($values as $key => $value) {
            $this->set($key, $value, $ttl);
        }
    }

    public function deleteMultiple($keys)
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }
    }

    public function has($key)
    {
        if (!isset($this->cache[$key])) {
            // does not exist
            return false;
        }
        if (isset($this->cache[$key][1]) && $this->cache[$key][1] < time()) {
            // expired
            return false;
        }
        return true;
    }

}
