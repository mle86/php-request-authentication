<?php

namespace mle86\RequestAuthentication\Tests\Helper;

use mle86\RequestAuthentication\Exception\DuplicateRequestIDException;
use mle86\RequestAuthentication\RequestIdList\RequestIdList;

trait RequestIdListTests
{
    use AssertException;


    abstract public function testGetInstance(): RequestIdList;


    /**
     * @depends testGetInstance
     */
    public function testEmptyInstance(RequestIdList $list): void
    {
        $this->assertFalse($list->contains('bd31912f334981727d761cf67f8100f2'));
        $this->assertFalse($list->contains('e10b3d6b589586fa576990353867f8b8'));
        $this->assertFalse($list->contains('b91d84e6108a0f3b4eb5f13d634085a0'));
    }

    /**
     * @depends testGetInstance
     * @depends testEmptyInstance
     */
    public function testPut(RequestIdList $list): void
    {
        $this->assertFalse($list->contains('6e90bc36872b7c4cebda0b6d0332be1d'));
        $list->put('6e90bc36872b7c4cebda0b6d0332be1d');
        $this->assertTrue($list->contains('6e90bc36872b7c4cebda0b6d0332be1d'));
    }

    /**
     * @depends testGetInstance
     * @depends testPut
     */
    public function testPutAgain(RequestIdList $list): void
    {
        $rqid = '6e90bc36872b7c4cebda0b6d0332be1d';
        $this->assertTrue($list->contains($rqid));
        $this->assertException(DuplicateRequestIDException::class, function() use($list, $rqid) {
            $list->put($rqid);
        });
        $this->assertTrue($list->contains($rqid));
    }

}
