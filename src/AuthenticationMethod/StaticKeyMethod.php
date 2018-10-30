<?php

namespace mle86\RequestAuthentication\AuthenticationMethod;

use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

/**
 * This authentication method consists of a simple “`X-API-Key`” header
 * that has some secret key value.
 *
 *  - The secret key value does not depend on the request data in any way.
 *
 *  - The `$api_client_id` input for the {@see authenticate} method is ignored
 *    and can always be set to the empty string.
 *
 *  - The secret key is used as the {@see KeyRepository} lookup key;
 *    the actual return value is ignored, as long as it's non-empty.
 *    For example, this would work:
 *
 *    `new ArrayRepository([ $secretKey => '1', … ])`
 *
 * @internal This authentication method should not be used in the real world, it is insecure.
 */
class StaticKeyMethod implements AuthenticationMethod
{

    const DEFAULT_HEADER_NAME = 'X-API-Key';

    private $headerName;
    public function __construct(string $headerName = self::DEFAULT_HEADER_NAME)
    {
        $headerName = rtrim($headerName, ':');
        if (!preg_match('/^[A-Za-z](?:[A-Za-z0-9\-]*[A-Za-z0-9])?$/', $headerName)) {
            throw new InvalidArgumentException('invalid header name');
        }

        $this->headerName = $headerName;
    }

    public function authenticate(RequestInfo $request, string $apiClientId, string $apiSecretKey): array
    {
        return [$this->headerName => $apiSecretKey];
    }

    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        if (!isset($keys[ $request->getNonemptyHeaderValue($this->headerName) ])) {
            throw new InvalidAuthenticationException('unknown api key');
        }
    }

    public function getClientId(RequestInfo $request): string
    {
        // We really shouldn't return the key header here, it contains the entire secret!
        // So we'll settle for some constant:
        return 'STATIC-KEY';
    }

}
