<?php

namespace mle86\RequestAuthentication\Crypto\Halite;

use mle86\RequestAuthentication\Exception\InvalidArgumentException;

trait HaliteKeyEncoding
{

    protected static function encodeKey(string $rawKey): string
    {
        return base64_encode($rawKey);
    }

    protected static function decodeKey(string $encodedKey): string
    {
        $decoded = base64_decode($encodedKey, true);

        if ($decoded === null || $decoded === false || $decoded === '') {
            throw new InvalidArgumentException('could not decode key');
        }

        return $decoded;
    }

}
