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
 *    `new ArrayRepository([ $secret_key => '1', … ])`
 *
 * @internal This authentication method should not be used in the real world, it is insecure.
 */
class StaticKeyMethod
    implements AuthenticationMethod
{

    const DEFAULT_HEADER_NAME = 'X-API-Key';

    private $header_name;
    public function __construct(string $header_name = self::DEFAULT_HEADER_NAME)
    {
        $header_name = rtrim($header_name, ':');
        if (!preg_match('/^[A-Za-z](?:[A-Za-z0-9\-]*[A-Za-z0-9])?$/', $header_name)) {
            throw new InvalidArgumentException('invalid header name');
        }

        $this->header_name = $header_name;
    }

    public function authenticate(RequestInfo $request, string $api_client_id, string $api_secret_key): array
    {
        return [$this->header_name => $api_secret_key];
    }

    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        if (!isset($keys[ $request->getNonemptyHeaderValue($this->header_name) ])) {
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
