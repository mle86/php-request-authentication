<?php
namespace mle86\RequestAuthentication\Crypto\Halite;

use mle86\RequestAuthentication\Exception\InvalidArgumentException;

trait HaliteKeyEncoding
{

    protected static function encodeKey(string $raw_key): string
    {
        return base64_encode($raw_key);
    }

    protected static function decodeKey(string $encoded_key): string
    {
        $decoded = base64_decode($encoded_key, true);

        if ($decoded === null || $decoded === false || $decoded === '') {
            throw new InvalidArgumentException('could not decode key');
        }

        return $decoded;
    }

}
