<?php

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\Crypto\Halite\HaliteSigningPrivateKey;
use mle86\RequestAuthentication\Crypto\Halite\HaliteSigningPublicKey;
use mle86\RequestAuthentication\Exception\CryptoErrorException;
use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\Tests\Helper\AssertException;
use PHPUnit\Framework\TestCase;

class HaliteAdapterTest extends TestCase
{
    use AssertException;

    public static function invalidKeyMaterial(): array { return [
        [''],
        ['QWJj'],
    ]; }

    public function testKeyGeneration(): HaliteSigningPrivateKey
    {
        // Two newly-generated keys should definitely be different:
        $priv1 = HaliteSigningPrivateKey::generate();
        $priv2 = HaliteSigningPrivateKey::generate();
        $this->assertNotEquals($priv1->getEncodedForm(), $priv2->getEncodedForm());

        // ...and they should have different public keys as well:
        $pub1  = HaliteSigningPublicKey::fromPrivateKey($priv1);
        $pub2  = HaliteSigningPublicKey::fromPrivateKey($priv2);
        $this->assertNotEquals($pub1->getEncodedForm(), $pub2->getEncodedForm());

        // But a public key, calculated from a private key, is deterministic:
        $pub11 = HaliteSigningPublicKey::fromPrivateKey($priv1);
        $this->assertEquals   ($pub1->getEncodedForm(), $pub11->getEncodedForm());

        return $priv1;
    }

    /**
     * @depends testKeyGeneration
     */
    public function testKeyEncoding(HaliteSigningPrivateKey $priv): void
    {
        $priv2 = new HaliteSigningPrivateKey($priv->getEncodedForm());
        $this->assertEquals($priv->getEncodedForm(), $priv2->getEncodedForm());

        $pub  = HaliteSigningPublicKey::fromPrivateKey($priv);
        $pub2 = new HaliteSigningPublicKey($pub->getEncodedForm());
        $this->assertEquals($pub->getEncodedForm(), $pub2->getEncodedForm());
    }

    /**
     * @dataProvider invalidKeyMaterial
     * @depends testKeyEncoding
     */
    public function testInvalidKeyEncoding(string $invalidKeyMaterial): void
    {
        $this->assertException([CryptoErrorException::class, InvalidArgumentException::class], function() use($invalidKeyMaterial) {
            new HaliteSigningPrivateKey($invalidKeyMaterial);
        });
        $this->assertException([CryptoErrorException::class, InvalidArgumentException::class], function() use($invalidKeyMaterial) {
            new HaliteSigningPublicKey($invalidKeyMaterial);
        });
    }

    // There's no need to test the other adapter methods any further
    // because the PublicKeyMethodTest will make heavy use of them.
    // Halite itself is well-tested.

}
