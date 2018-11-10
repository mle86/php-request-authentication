<?php

namespace mle86\RequestAuthentication\Crypto\Sha1Hash;

use mle86\RequestAuthentication\Crypto\Hasher;
use mle86\RequestAuthentication\Exception\InvalidArgumentException;

/**
 * Calculates and verifies `{SSHA}xxxxxxxxxxxxxxxxxxxxxxxxxxxx` hashes
 * as traditionally used in some htpasswd files.
 */
class SaltedSha1HtpasswdHasher extends Hasher
{

    public const PREFIX = '{SSHA}';

    private const SALT_LENGTH = 4;

    public function hash(string $message, string $salt = null): string
    {
        if ($salt === null || $salt === '') {
            // 3 raw bytes always equal 4 base64 characters.
            $salt = base64_encode(random_bytes(3));
        }
        if (strlen($salt) !== self::SALT_LENGTH) {
            throw new InvalidArgumentException('invalid salt');
        }

        $rawHash           = sha1($message . $salt, true);
        $rawSaltedHash     = $rawHash . $salt;
        $encodedSaltedHash = base64_encode($rawSaltedHash);

        return self::PREFIX . $encodedSaltedHash;
    }

    public function test(string $inputMessage, string $knownHash): bool
    {
        $prefixLen = strlen(self::PREFIX);

        // If we cannot extract the used salt from the knownHash,
        // we'll just run hash() with some other constant salt.
        // It certainly won't match but it'll waste an appropriate amount of time.
        $usedSalt = 'AAAA';

        $knownDecodedHash = base64_decode(substr($knownHash, $prefixLen), true);
        if ($knownDecodedHash !== false && strlen($knownDecodedHash) >= self::SALT_LENGTH) {
            $usedSalt = substr($knownDecodedHash, -4);
        }

        $inputHash = rtrim($this->hash($inputMessage, $usedSalt), '=');
        return hash_equals(
            rtrim($knownHash, '='),
            rtrim($inputHash, '='));
    }

}
