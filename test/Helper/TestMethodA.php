<?php

namespace mle86\RequestAuthentication\Tests\Helper;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

/**
 * This AuthenticationMethod implementation
 * has a `X-Test-Signature` header with a random even positive number between 1000..1999.
 * and a `X-Test-Client` header with the client id.
 *
 * The client secret is not used.
 * The key repository is not used.
 *
 * It is very similar to {@see TestMethodB}
 * which uses the same headers
 * but expects the signature value to be odd
 * (but still in range 1000..1999).
 */
class TestMethodA implements AuthenticationMethod
{

    const SIGNATURE_HEADER = 'X-Test-Signature';
    const CLIENT_HEADER    = 'X-Test-Client';

    public function authenticate(RequestInfo $request, string $apiClientId, string $apiSecretKey): array
    {
        return [
            self::CLIENT_HEADER    => $apiClientId,
            self::SIGNATURE_HEADER => 2 * random_int(500, 999),  // 500..999 x2 = 1000..1998 (even)
        ];
    }

    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        $this->getClientId($request);  // value required but not validated

        $sig = $request->getNonemptyHeaderValue(self::SIGNATURE_HEADER);
        $isEvenInteger = (
            (is_int($sig) || ctype_digit($sig)) &&
            $sig >= 1000 && $sig <= 1999 &&
            ($sig % 2) === 0);
        if (!$isEvenInteger) {
            throw new InvalidAuthenticationException('invalid signature value');
        }
    }

    public function getClientId(RequestInfo $request): string
    {
        return $request->getNonemptyHeaderValue(self::CLIENT_HEADER);
    }
}
