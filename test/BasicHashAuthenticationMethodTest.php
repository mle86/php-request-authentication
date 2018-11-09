<?php

namespace mle86\RequestAuthentication\Tests;

use GuzzleHttp\Psr7\Request;
use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\AuthenticationMethod\BasicAuthenticationMethod;
use mle86\RequestAuthentication\AuthenticationMethod\BasicHashAuthenticationMethod;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\KeyRepository\ArrayRepository;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;
use mle86\RequestAuthentication\Tests\Helper\AuthenticationMethodTests;
use PHPUnit\Framework\TestCase;

class BasicHashAuthenticationMethodTest extends TestCase
{
    use AuthenticationMethodTests;

    protected function methodOutputDependsOnRequestData(): bool
    {
        // It's just a header containing the username and the password, it doesn't change if the input changes.
        return false;
    }

    public function customDifferentAuthenticationData(): array { return [
        // sampleClientId and otherClientId are always tested
        // (in testSampleRequest and testOtherClientAuthentications).
        // But we more client keys here to test
        // because their KeyRepository entries were build with different hashing methods!
        ['xc3', 'y6eDuQl6'],
#       ['xc4', 'exNJEw0y'],
    ]; }

    protected function getTestingKeyRepository(): KeyRepository
    {
        return new ArrayRepository($this->customKeyRepositoryEntries() + [
                // PhpHasher, bcrypt/password_hash(PASSWORD_BCRYPT):
                self::sampleClientId() => '$2y$10$ZcXil/lDIoQuGMQkFZnPtOTKoQ7pPUs.OUtAC.C7XpynkQCq.MXP.',
                // (calculated from AuthenticationMethodTestDefaults::sampleClientKey)

                // Sha1HtpasswdHasher:
                self::otherClientId() => '{SHA}qnpNnYHNYxgpHXtleaWKGnuevJ0=',
                // (calculated from AuthenticationMethodTestDefaults::otherClientKey)

                // PhpHasher, crypt(EXT_DES):
                'xc3' => '_00023cnQeSGjmIuQZsE',

                // Argon2i hashes are supported natively starting with PHP7.2.
                // This is a PHP7.1 library
                // so we cannot have this as part of our official tests yet.
#               // PhpHasher, password_hash(PASSWORD_ARGON2I):
#              'xc4' => '$argon2i$v=19$m=1024,t=2,p=2$em9nRzZyS2dyeTIxVFplaQ$0xOWGXs5ZjCnKiJ+/bxQJ3QZe8eouHwgL3fPt738KVU',
            ]);
    }


    public function testGetInstance(): AuthenticationMethod
    {
        return new BasicHashAuthenticationMethod();
    }

    public function testGetAuthenticationMethod(): BasicAuthenticationMethod
    {
        return new BasicAuthenticationMethod();
    }

    public function testGetVerificationMethod(): BasicHashAuthenticationMethodTest
    {
        return new BasicHashAuthenticationMethodTest();
    }

    # TODO...
}
