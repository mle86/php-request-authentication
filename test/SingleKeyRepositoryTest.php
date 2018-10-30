<?php

declare(strict_types=1);

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;
use mle86\RequestAuthentication\KeyRepository\SingleKeyRepository;
use mle86\RequestAuthentication\Tests\Helper\AssertException;
use mle86\RequestAuthentication\Tests\Helper\KeyRepositoryTests;
use PHPUnit\Framework\TestCase;

class SingleKeyRepositoryTest extends TestCase
{
    use AssertException;
    use KeyRepositoryTests;


    const SINGLE_CLIENT_ID  = 'y111';
    const SINGLE_CLIENT_KEY = 'K999';

    public static function defaultData(): array {
        return [self::SINGLE_CLIENT_ID => self::SINGLE_CLIENT_KEY];
    }

    public function testGetInstance(): KeyRepository
    {
        return new SingleKeyRepository(self::SINGLE_CLIENT_ID, self::SINGLE_CLIENT_KEY);
    }

    /**
     * @dataProvider invalidClientIDs
     * @depends testGetInstance
     */
    public function testInvalidClientIDsInConstructor($invalidClientId): void
    {
        $validKey = array_values(self::defaultData())[0];

        $this->assertException([InvalidArgumentException::class, \TypeError::class], function() use($invalidClientId, $validKey) {
            new SingleKeyRepository($invalidClientId, $validKey);
        });
    }

    /**
     * @dataProvider invalidClientKeys
     * @depends testGetInstance
     */
    public function testInvalidClientKeysInConstructor($invalidClientKey): void
    {
        $validId = array_keys(self::defaultData())[0];

        $this->assertException([InvalidArgumentException::class, \TypeError::class], function() use($invalidClientKey, $validId) {
            new SingleKeyRepository($validId, $invalidClientKey);
        });
    }

}
