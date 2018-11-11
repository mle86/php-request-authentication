<?php

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\AuthenticationMethod\StaticKeyMethod;
use mle86\RequestAuthentication\KeyRepository\ArrayRepository;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;
use mle86\RequestAuthentication\Tests\Helper\AuthenticationMethodTests;
use PHPUnit\Framework\TestCase;

class StaticKeyMethodTest extends TestCase
{
    use AuthenticationMethodTests;

    protected function methodOutputDependsOnRequestData(): bool
    {
        // It's just a header containing some key, it doesn't change if the input changes.
        return false;
    }

    protected function methodOutputIncludesClientId(): bool
    {
        // The static key header does not include any client identification -- there is none.
        return false;
    }

    protected function getTestingKeyRepository(): KeyRepository
    {
        return new ArrayRepository([
            // The default client IDs "C1" and "C11" are completely irrelevant for this method --
            // they won't make it into the output.
            self::sampleClientKey() => 'any-nonnull-value',
            self::otherClientKey()  => '1',  // cannot be empty, the KeyRepository does not like that
        ]);
    }

    public function testGetInstance(): AuthenticationMethod
    {
        return new StaticKeyMethod();
    }

    /**
     * @depends testGetInstance
     */
    public function testInvalidInstantiation(): void
    {
        $this->assertException(\InvalidArgumentException::class, function() {
            // invalid header name
            return new StaticKeyMethod('invalid!header ...');
        });
    }

}