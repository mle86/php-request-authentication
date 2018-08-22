<?php

namespace mle86\RequestAuthentication\Tests\Helper;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

/**
 * This AuthenticationMethod implementation
 * has a `X-Test-Signature` header with a random even positive number
 * and a `X-Test-Client` header with the client id.
 *
 * The client secret is not used.
 * The key repository is not used.
 *
 * It is very similar to {@see TestMethodB}
 * which uses the same headers
 * but expects the signature value to be odd.
 */
class TestMethodA
    implements AuthenticationMethod
{

    const SIGNATURE_HEADER = 'X-Test-Signature';
    const CLIENT_HEADER    = 'X-Test-Client';

    public function authenticate(RequestInfo $request, string $api_client_id, string $api_secret_key): array
    {
        return [
            self::CLIENT_HEADER    => $api_client_id,
            self::SIGNATURE_HEADER => 2 * random_int(1, 1000),
        ];
    }

    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        $this->getClientId($request);  // value required but not validated

        $sig = $request->getNonemptyHeaderValue(self::SIGNATURE_HEADER);
        $is_even_integer = (
            (is_int($sig) || ctype_digit($sig)) &&
            $sig > 0 &&
            ($sig % 2) === 0);
        if (!$is_even_integer) {
            throw new InvalidAuthenticationException('invalid signature value');
        }
    }

    public function getClientId(RequestInfo $request): string
    {
        return $request->getNonemptyHeaderValue(self::CLIENT_HEADER);
    }
}
