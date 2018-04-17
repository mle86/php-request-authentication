<?php
namespace mle86\RequestAuthentication\AuthenticationMethod\Feature;

use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;

trait HexRequestIDTrait
{

    protected static function validateRequestId($request_id): void
    {
        if (!is_string($request_id) || $request_id === '' || $request_id === null) {
            throw new InvalidAuthenticationException('no request_id');
        }

        $request_id_len = strlen($request_id);
        if ($request_id_len < self::REQUEST_ID_MIN_LEN || $request_id_len > self::REQUEST_ID_MAX_LEN) {
            throw new InvalidAuthenticationException('request id has invalid length');
        }

        if (!ctype_xdigit($request_id)) {
            throw new InvalidAuthenticationException('request id invalid');
        }
    }

    public function generateRequestId(): string
    {
        return hash(self::REQUEST_ID_HASH_ALGO, random_bytes(self::REQUEST_ID_RANDOM_BYTES));
    }

}
