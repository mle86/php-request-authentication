<?php

declare(strict_types=1);

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\Crypto\Apr1Hash\Apr1Hasher;
use mle86\RequestAuthentication\Crypto\Hasher;
use mle86\RequestAuthentication\Crypto\HasherFactory;
use mle86\RequestAuthentication\Crypto\PhpHash\PhpHasher;
use mle86\RequestAuthentication\Crypto\Sha1Hash\SaltedSha1HtpasswdHasher;
use mle86\RequestAuthentication\Crypto\Sha1Hash\Sha1HtpasswdHasher;
use mle86\RequestAuthentication\Exception\HashMethodUnknownException;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use PHPUnit\Framework\TestCase;

class HasherTest extends TestCase
{

    public static function knownHashers(): array { return [
        [new PhpHasher()],
        [new Sha1HtpasswdHasher()],
        [new SaltedSha1HtpasswdHasher()],
        [new Apr1Hasher()],
    ]; }

    public static function correctPasswords(): array { return [
        ['LWdtOcNi6G4i06rBZdQvhjliAYgDec1'],
        ['!01'],
    ]; }

    public static function incorrectPasswords(): array { return [
        ['b10NA2PIUxUlH0IDLtJLMuZDHhYn3ysdv'],
        ['!'],
    ]; }

    public static function otherHashFormats(): array { return [
        // Some Hasher classes can verify more than one hash format
        // but testHashFactory will only test their default output format.
        // [hash, correctPassword]
        ['$1$YjQY3TxK$3c0vNGHVtHbBZmeG3WlSz1', 'S5Aa3gi9f'],  // $1$ == crypt(md5), PhpHasher
        ['Yz3.F7/HvZke.',                      'r6EaXSyVL'],  // crypt(DES), PhpHasher
        ['_001190A0X83g85l.2zo',               '1HVS02YWk'],  // crypt(EXT_DES), PhpHasher
    ]; }

    public static function unknownHashFormats(): array { return [
        // Invalid hashes should cause an exception
        ['!~@89579948tziugf='],
    ]; }

    public static function hashersXcorrectPasswords(): array
    {
        return self::cartesian(['hasher' => self::knownHashers(), 'correctPassword' => self::correctPasswords()]);
    }

    public static function hashersXincorrectPasswords(): array
    {
        return self::cartesian(['hasher' => self::knownHashers(), 'incorrectPassword' => self::incorrectPasswords()]);
    }


    /**
     * @dataProvider hashersXcorrectPasswords
     */
    public function testCorrectPassword(Hasher $hasher, string $correctPassword): void
    {
        $hash = $hasher->hash($correctPassword);
        $hasher->verify($correctPassword, $hash);
    }

    /**
     * @dataProvider hashersXincorrectPasswords
     */
    public function testIncorrectPassword(Hasher $hasher, string $incorrectPassword): void
    {
        $hash = $hasher->hash(self::correctPasswords()[0][0]);
        $this->expectException(InvalidAuthenticationException::class);
        $hasher->verify($incorrectPassword, $hash);
    }

    /**
     * @dataProvider knownHashers
     */
    public function testMalformedHash(Hasher $hasher): void
    {
        $this->assertFalse($hasher->test('',                     ''));
        $this->assertFalse($hasher->test('',                     '!'));
        $this->assertFalse($hasher->test('SnfoSEtTotpWC1JBYn9r', ''));
        $this->assertFalse($hasher->test('SnfoSEtTotpWC1JBYn9r', '!'));
    }

    public function testHashFactoryInstance(): HasherFactory
    {
        return new HasherFactory();
    }

    /**
     * @dataProvider knownHashers
     * @depends testHashFactoryInstance
     * @depends testCorrectPassword
     */
    public function testHashFactory(Hasher $hasher, HasherFactory $factory): void
    {
        $hash = $hasher->hash(self::correctPasswords()[0][0]);

        $hasherFromFactory = $factory->getHasher($hash);

        $this->assertSame(
            get_class($hasher),
            get_class($hasherFromFactory));
    }

    /**
     * @dataProvider otherHashFormats
     * @depends testHashFactoryInstance
     * @depends testHashFactory
     */
    public function testHashFactoryOtherFormat(string $hash, string $correctPassword, HasherFactory $factory): void
    {
        $hasher = $factory->getHasher($hash);

        $this->assertTrue ($hasher->test($correctPassword, $hash));

        $this->assertFalse($hasher->test('CC5Vy790DNELN8uDJbAkLw', $hash));
        $this->assertFalse($hasher->test('', $hash));
        $this->assertFalse($hasher->test("\0" . $correctPassword, $hash));
    }

    /**
     * @dataProvider unknownHashFormats
     * @depends testHashFactoryInstance
     * @depends testHashFactory
     */
    public function testHashFactoryUnknownFormat(string $unknownHash, HasherFactory $factory): void
    {
        $this->expectException(HashMethodUnknownException::class);
        $factory->getHasher($unknownHash);
    }


    private static function cartesian(array $input): array
    {
        // https://stackoverflow.com/a/15973172
        $input  = array_filter($input);
        $result = [[]];
        foreach ($input as $key => $values) {
            $append = [];
            foreach ($result as $product) {
                foreach ($values as $item) {
                    $product[$key] = $item[0];
                    $append[]      = $product;
                }
            }
            $result = $append;
        }
        return $result;
    }

}
