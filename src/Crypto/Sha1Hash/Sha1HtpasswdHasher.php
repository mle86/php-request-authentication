<?php

namespace mle86\RequestAuthentication\Crypto\Sha1Hash;

use mle86\RequestAuthentication\Crypto\Hasher;

/**
 * Calculates and verifies `{SHA}xxxxxxxxxxxxxxxxxxxxxxxxxxxx` hashes
 * as traditionally used in some htpasswd files.
 */
class Sha1HtpasswdHasher extends Hasher
{

    public const PREFIX = '{SHA}';

    public function hash(string $message): string
    {
        $rawHash     = sha1($message, true);
        $encodedHash = base64_encode($rawHash);

        return self::PREFIX . $encodedHash;
    }

}
