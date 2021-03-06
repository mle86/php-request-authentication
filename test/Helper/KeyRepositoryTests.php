<?php

declare(strict_types=1);

namespace mle86\RequestAuthentication\Tests\Helper;

use mle86\RequestAuthentication\Exception\ImmutableDataException;
use mle86\RequestAuthentication\Exception\UnknownClientIdException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

trait KeyRepositoryTests
{

    // Required methods:  //////////////////////////////////////////////////////

    abstract public function testGetInstance(): KeyRepository;


    // Default providers:  /////////////////////////////////////////////////////

    /**
     * Make sure that the instance returned by {@see testGetInstance}
     * always contains at least these client IDs and keys.
     *
     * (This is not a dataProvider.)
     *
     * If your repository class is absolutely unable of returning these values,
     * override the method with a custom implementation --
     * but make sure that it returns _at least one_ id/key pair.
     *
     * @return array[]  [clientId => clientKey, …]
     */
    public static function defaultData(): array { return [
        'a1' => 'V1',
        'b2' => 'V11',
    ]; }

    /**
     * Make sure that the instance returned by {@see testGetInstance}
     * never contains any of these client IDs.
     *
     * @return mixed[][]
     */
    public static function unknownKeys(): array { return [
        ['a'],
        ['a0'],
        ['0'],
        [0],
        [''],
        [' '],
        [null],
    ]; }

    /**
     * These client IDs are considered invalid.
     *
     * {@see KeyRepository::offsetExists} should always return `false` for them
     * (but this is already ensured by the {@see unknownKeys} provider).
     *
     * Your test class should ensure that the constructor fails on those client IDs.
     *
     * @return mixed[][]
     */
    public static function invalidClientIDs(): array { return [
        [null],
        [''],
        [0],
        [false],
    ]; }

    /**
     * These client secrets are considered invalid.
     *
     * Your test class should ensure that the constructor fails on those client IDs.
     *
     * @return mixed[][]
     */
    public static function invalidClientKeys(): array { return [
        [null],
        [''],
        [0],
        [false],
        [-3.3],
        [array()],
        [new \stdClass()],
    ]; }


    // Default tests:  /////////////////////////////////////////////////////////

    /**
     * @dataProvider unknownKeys
     * @depends testGetInstance
     */
    public function testUnknownKeys($unknownKey, KeyRepository $keys): void
    {
        $this->assertFalse(isset($keys[$unknownKey]));
        $this->assertException(UnknownClientIdException::class, function() use($keys, $unknownKey) {
            $x = $keys[$unknownKey];
            unset($x);
        });
    }

    /**
     * @depends testGetInstance
     */
    public function testKnownKeys(KeyRepository $keys): void
    {
        foreach (static::defaultData() as $key => $value) {
            $this->assertTrue(isset($keys[$key]));
            $this->assertSame($value, $keys[$key]);
        }
    }


    /**
     * @depends testGetInstance
     * @depends testKnownKeys
     * @depends testUnknownKeys
     */
    public function testImmutableRepository(KeyRepository $keys): void
    {
        $keys = clone $keys;

        $setto         = '#990199';
        $existingKey   = array_keys  (static::defaultData())[0];
        $existingValue = array_values(static::defaultData())[0];
        $unknownKey    = self::unknownKeys()[0][0];

        $this->assertException(ImmutableDataException::class, function() use(&$keys, $existingKey, $setto) {
            $keys[$existingKey] = $setto;
        });
        $this->assertNotSame($setto, $keys[$existingKey],
            'Write access to existing key caused an exception, but still changed the value!');

        $this->assertException(ImmutableDataException::class, function() use(&$keys, $existingKey) {
            unset($keys[$existingKey]);
        });
        $this->assertTrue(isset($keys[$existingKey]),
            'unset() against an existing key caused an exception, but still removed the key!');
        $this->assertSame($existingValue, $keys[$existingKey],
            'unset() against an existing key caused an exception, but still changed the value!');

        $this->assertException(ImmutableDataException::class, function() use(&$keys, $unknownKey, $setto) {
            $keys[$unknownKey] = $setto;
        });
        $this->assertFalse(isset($keys[$unknownKey]),
            'Write access to an unknown key caused an exception, but still created the key!');
    }


    /**
     * This test method depends on _all_ previous tests.
     *
     * @see otherTests
     *
     * @depends testGetInstance
     */
    public function testOther(KeyRepository $repo): void
    {
        $this->otherTests($repo);
    }

    /**
     * If you want to add custom tests to your Test class
     * which should run after all the trait test methods have passed,
     * override this function.
     *
     * It will be called by {@see testOther} at the end.
     *
     * @param KeyRepository $repo  The instance returned by {@see testGetInstance()}.
     */
    protected function otherTests(KeyRepository $repo): void
    {
    }

}
