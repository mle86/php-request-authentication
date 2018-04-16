<?php
namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\KeyRepository\ArrayRepository;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;
use mle86\RequestAuthentication\Tests\Helper\AssertException;
use mle86\RequestAuthentication\Tests\Helper\KeyRepositoryTests;
use PHPUnit\Framework\TestCase;

class ArrayRepositoryTest
    extends TestCase
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
    public function testInvalidClientIDsInConstructor($invalid_client_id): void
    {
        $valid_key = array_values(self::defaultData())[0];

        $this->assertException(InvalidArgumentException::class, function() use($invalid_client_id, $valid_key) {
            new ArrayRepository([$invalid_client_id => $valid_key]);
        });
    }

    /**
     * @dataProvider invalidClientKeys
     * @depends testGetInstance
     */
    public function testInvalidClientKeysInConstructor($invalid_client_key): void
    {
        $valid_id = array_keys(self::defaultData())[0];

        $this->assertException(InvalidArgumentException::class, function() use($invalid_client_key, $valid_id) {
            new ArrayRepository([$valid_id => $invalid_client_key]);
        });
    }

}
