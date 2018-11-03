<?php

namespace mle86\RequestAuthentication\Crypto\PhpHash;

use mle86\RequestAuthentication\Crypto\Hasher;

/**
 * Computes hashes using {@see password_hash}.
 * Verifies hashes created by {@see password_hash} or {@see crypt}.
 */
class PhpHasher extends Hasher
{

    private $hashAlgo;

    public function __construct(int $hashAlgo = \PASSWORD_DEFAULT)
    {
        $this->hashAlgo = $hashAlgo;
    }

    public function hash(string $message): string
    {
        return password_hash($message, $this->hashAlgo);
    }

    public function test(string $inputMessage, string $hash): bool
    {
        /*
         * This override is needed
         * because the output of password_hash() is _not_ deterministic,
         * it usually includes a randomly generated salt.
         */

        if ($hash === '' || $hash === '*' || $hash === '!') {
            // Those are always invalid. Waste some time and abort:
            password_verify($inputMessage, '$2y$10$e4s61ML2/WMpg4BM9JB/VudE38dpKiQ013byL1qVELY2DUuowPkJG');
            return false;
        }

        return password_verify($inputMessage, $hash);
    }

}
