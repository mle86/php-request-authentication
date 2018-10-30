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
    public function testInvalidClientIDsInConstructor($invalid_client_id): void
    {
        $valid_key = array_values(self::defaultData())[0];

        $this->assertException([InvalidArgumentException::class, \TypeError::class], function() use($invalid_client_id, $valid_key) {
            new SingleKeyRepository($invalid_client_id, $valid_key);
        });
    }

    /**
     * @dataProvider invalidClientKeys
     * @depends testGetInstance
     */
    public function testInvalidClientKeysInConstructor($invalid_client_key): void
    {
        $valid_id = array_keys(self::defaultData())[0];

        $this->assertException([InvalidArgumentException::class, \TypeError::class], function() use($invalid_client_key, $valid_id) {
            new SingleKeyRepository($valid_id, $invalid_client_key);
        });
    }

}
