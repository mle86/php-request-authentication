<?php

declare(strict_types=1);

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\Crypto\Hasher;
use mle86\RequestAuthentication\Crypto\HasherFactory;
use mle86\RequestAuthentication\Crypto\PhpHash\PhpHasher;
use mle86\RequestAuthentication\Crypto\Sha1Hash\Sha1HtpasswdHasher;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use PHPUnit\Framework\TestCase;

class HasherTest extends TestCase
{

    public static function knownHashers(): array { return [
        [new PhpHasher()],
        [new Sha1HtpasswdHasher()],
    ]; }

    public static function correctPasswords(): array { return [
        ['LWdtOcNi6G4i06rBZdQvhjliAYgDec1'],
        ['!01'],
    ]; }

    public static function incorrectPasswords(): array { return [
        ['b10NA2PIUxUlH0IDLtJLMuZDHhYn3ysdv'],
        ['!'],
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
