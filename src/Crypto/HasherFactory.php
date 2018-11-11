<?php

namespace mle86\RequestAuthentication\Crypto;

use mle86\RequestAuthentication\Crypto\PhpHash\PhpHasher;
use mle86\RequestAuthentication\Crypto\Sha1Hash\SaltedSha1HtpasswdHasher;
use mle86\RequestAuthentication\Crypto\Sha1Hash\Sha1HtpasswdHasher;
use mle86\RequestAuthentication\Exception\HashMethodNotImplementedException;
use mle86\RequestAuthentication\Exception\HashMethodUnknownException;
use function substr, strlen;

/**
 * Analyzes the prefix of hashes
 * and returns a {@see Hasher} instance
 * that can verify the hash against a known password.
 *
 * Currently supported:
 *  - Hashes created by {@see password_hash()}.
 *  - Hashes created by {@see crypt()}.
 *  - Hashes created by any {@see Hasher} class included in this library.
 *  - SHA1 htpasswd hashes ("`{SHA}`").
 */
class HasherFactory
{

    public function getHasher(string $hash): Hasher
    {
        $algoInfo = password_get_info($hash);
        if ($algoInfo && $algoInfo['algoName'] !== 'unknown') {
            // This hash was created by password_hash().
            return new PhpHasher();
        }

        if (self::isPrefix($hash, ['$1$', '$2a$', '$2x$', '$2y$', '$5$', '$6$'])) {
            // This hash was created by crypt().
            // The PhpHasher can handle them.
            return new PhpHasher();
        }

        if (self::isCryptDesHash($hash)) {
            // crypt DES/EXT-DES
            return new PhpHasher();
        }

        if (self::isPrefix($hash, [Sha1HtpasswdHasher::PREFIX])) {
            return new Sha1HtpasswdHasher();
        }

        if (self::isPrefix($hash, [SaltedSha1HtpasswdHasher::PREFIX])) {
            return new SaltedSha1HtpasswdHasher();
        }

        if (self::isPrefix($hash, ['$apr1$'])) {
            # TODO
            throw HashMethodNotImplementedException::withDefaultMessage('APR1');
        }

        throw HashMethodUnknownException::withDefaultMessage();
    }


    private static function isPrefix(string $hash, array $prefixes): bool
    {
        foreach ($prefixes as $prefix) {
            if (substr($hash, 0, strlen($prefix)) === $prefix) {
                return true;
            }
        }

        return false;
    }

    private static function isCryptDesHash(string $hash): bool
    {
        if (strlen($hash) === 13) {
            // crypt DES
            return true;
        }
        if (strlen($hash) === 20 && $hash[0] === '_') {
            // crypt EXT DES
            return true;
        }
        return false;
    }

}
