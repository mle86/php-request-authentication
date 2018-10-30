<?php

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\KeyRepository\ArrayRepository;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;
use mle86\RequestAuthentication\Tests\Helper\AssertException;
use mle86\RequestAuthentication\Tests\Helper\KeyRepositoryTests;
use PHPUnit\Framework\TestCase;

class ArrayRepositoryTest extends TestCase
{
    use AssertException;
    use KeyRepositoryTests;


    public function testGetInstance(): KeyRepository
    {
        return new ArrayRepository(self::defaultData());
    }

    /**
     * @dataProvider invalidClientIDs
     * @depends testGetInstance
     */
    public function testInvalidClientIDsInConstructor($invalidClientId): void
    {
        $validKey = array_values(self::defaultData())[0];

        $this->assertException(InvalidArgumentException::class, function() use($invalidClientId, $validKey) {
            new ArrayRepository([$invalidClientId => $validKey]);
        });
    }

    /**
     * @dataProvider invalidClientKeys
     * @depends testGetInstance
     */
    public function testInvalidClientKeysInConstructor($invalidClientKey): void
    {
        $validId = array_keys(self::defaultData())[0];

        $this->assertException(InvalidArgumentException::class, function() use($invalidClientKey, $validId) {
            new ArrayRepository([$validId => $invalidClientKey]);
        });
    }

}
