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

    public function testGetInstance(): RequestIdList
    {
        $memCache  = new MemoryCache();
        $cacheList = new CacheRequestIdList($memCache, '_test_');
        return $cacheList;
    }

    # TODO: test cache key usage

}
