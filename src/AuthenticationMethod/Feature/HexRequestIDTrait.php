<?php

namespace mle86\RequestAuthentication\AuthenticationMethod\Feature;

use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;

trait HexRequestIDTrait
{

    protected static function validateRequestId($requestId): void
    {
        if (!is_string($requestId) || $requestId === '' || $requestId === null) {
            throw new InvalidAuthenticationException('no request id');
        }

        $requestIdLen = strlen($requestId);
        if ($requestIdLen < self::REQUEST_ID_MIN_LEN || $requestIdLen > self::REQUEST_ID_MAX_LEN) {
            throw new InvalidAuthenticationException('request id has invalid length');
        }

        if (!ctype_xdigit($requestId)) {
            throw new InvalidAuthenticationException('request id invalid');
        }
    }

    public function generateRequestId(): string
    {
        return hash(self::REQUEST_ID_HASH_ALGO, random_bytes(self::REQUEST_ID_RANDOM_BYTES));
    }

}
