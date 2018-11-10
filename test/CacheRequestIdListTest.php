<?php

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\RequestIdList\CacheRequestIdList;
use mle86\RequestAuthentication\RequestIdList\RequestIdList;
use mle86\RequestAuthentication\Tests\Helper\MemoryCache;
use mle86\RequestAuthentication\Tests\Helper\RequestIdListTests;
use PHPUnit\Framework\TestCase;

class CacheRequestIdListTest extends TestCase
{
    use RequestIdListTests;

    private const CACHE_KEY_PREFIX = '_test';

    private static $cache;
    private static function getCache(): MemoryCache
    {
        if (!self::$cache) {
            self::$cache = new MemoryCache();
            self::$cache->set('myKey', 'myValue');
        }

        return self::$cache;
    }

    public function testGetInstance(): RequestIdList
    {
        return new CacheRequestIdList(self::getCache(), self::CACHE_KEY_PREFIX);
    }


    protected function otherTests(): void
    {
        $this->checkCacheKeys();
    }

    protected function checkCacheKeys(): void
    {
        $regex = '/^(myKey|' . preg_quote(self::CACHE_KEY_PREFIX, '/') . '.+)/';

        $this->assertSame('myValue', self::getCache()->get('myKey'));

        foreach (self::getCache()->getAllKeys() as $cacheKey) {
            $this->assertRegExp($regex, $cacheKey);
        }
    }


}
