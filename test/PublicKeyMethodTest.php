<?php

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\AuthenticationMethod\PublicKeyMethod;
use mle86\RequestAuthentication\Crypto\Halite\HaliteSigningPublicKey;
use mle86\RequestAuthentication\Crypto\Halite\HaliteSigningPrivateKey;
use mle86\RequestAuthentication\Tests\Helper\AuthenticationMethodTests;
use mle86\RequestAuthentication\Tests\Helper\RunID;
use ParagonIE\Halite\KeyFactory;
use ParagonIE\Halite\SignatureKeyPair;
use PHPUnit\Framework\TestCase;

class PublicKeyMethodTest extends TestCase
{
    use AuthenticationMethodTests;
    use RunID;

    private static $defaultKeyPair;
    private static function generateDefaultKeyPair(): SignatureKeyPair
    {
        return (self::$defaultKeyPair ?? (self::$defaultKeyPair =
            KeyFactory::generateSignatureKeyPair()
        ));
    }

    private static $otherKeyPair;
    private static function generateOtherKeyPair(): SignatureKeyPair
    {
        return (self::$otherKeyPair ?? (self::$otherKeyPair =
            KeyFactory::generateSignatureKeyPair()
        ));
    }

    public static function sampleClientKey(): string { return HaliteSigningPrivateKey::fromKeyPair(self::generateDefaultKeyPair())->getEncodedForm(); }
    public static function otherClientKey(): string  { return HaliteSigningPrivateKey::fromKeyPair(self::generateOtherKeyPair())  ->getEncodedForm(); }

    public function customKeyRepositoryEntries(): array { return [
        self::sampleClientId() => HaliteSigningPublicKey::fromKeyPair(self::generateDefaultKeyPair())->getEncodedForm(),
        self::otherClientId()  => HaliteSigningPublicKey::fromKeyPair(self::generateOtherKeyPair())  ->getEncodedForm(),
    ]; }

    public function differentClientData(): array { return [
        /* Some of the original differentClientData() entries contain keys that cannot be decoded correctly,
         * which would lead to InvalidArgumentExceptions/CryptoExceptions. That's not what we want to test here,
         * so we'll emit only valid-looking (but still incorrect) keys:  */
        [['key' => self::otherClientKey()]],
        [['key' => 'y' . substr(self::sampleClientKey(), 1)]],
    ]; }


    public function testGetInstance(): AuthenticationMethod
    {
        return new PublicKeyMethod();
    }

    protected function defaultRequestHeaders(): array { return [
        // We want all of our test requests to carry the exact same request id, so we'll add it manually before calling authenticate():
        PublicKeyMethod::DEFAULT_REQUEST_ID_HEADER => self::runId(),
    ]; }


    /**
     * Not all values in {@see AuthenticationMethodTests::invalidAuthenticationHeaderValues()}
     * are suitable to test the `X-Request-ID` header,
     * because some of them actually look pretty valid for that header...
     */
    protected function authenticationHeaders(): array { return [
        PublicKeyMethod::SIGNATURE_HEADER,
        PublicKeyMethod::CLIENT_ID_HEADER,
    ]; }

    protected function otherTests(AuthenticationMethod $method, array $originalAddHeaders): void
    {
        $this->checkRepeatedPayloadHeader($method, $this->applyHeaders($this->buildRequest(), $originalAddHeaders),
            'Content-Type');
    }

}
