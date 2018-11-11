<?php

namespace mle86\RequestAuthentication\Crypto\Apr1Hash;

use mle86\RequestAuthentication\Crypto\Hasher;
use WhiteHat101\Crypt\APR1_MD5;

/**
 * Calculates and verifies `$apr1$ssssssss$xxxxxxxxxxxxxxxxxxxxxx` hashes
 * as tradiditionally used in many htpasswd files.
 *
 * @see https://packagist.org/packages/whitehat101/apr1-md5 This uses the whitehat101/apr1-md5 package.
 */
class Apr1Hasher extends Hasher
{

    public const PREFIX = '$apr1$';

    private const SALT_LEN = 8;

    public function hash(string $message, string $salt = null): string
    {
        return APR1_MD5::hash($message, $salt);
    }

    public function test(string $inputMessage, string $hash): bool
    {
        $salt = substr($hash, strlen(self::PREFIX), self::SALT_LEN);

        if (strlen($salt) !== self::SALT_LEN) {
            // If we cannot extract the used salt from the knownHash,
            // we'll just run hash() with some other constant salt.
            // It certainly won't match but it'll waste an appropriate amount of time.
            $salt = 'AAAA';
        }

        return hash_equals($hash, $this->hash($inputMessage, $salt));
    }

}
