<?php

namespace mle86\RequestAuthentication\AuthenticationMethod;

use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\CryptoErrorException;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

/**
 * Implements HTTP “Basic” authentication.
 *
 * The Basic username is the $apiClientId,
 * the Basic password is the $apiClientKey.
 * The Basic password must also be returned unchanged by the KeyRepository.
 *
 * If you want to store the Basic password in hashed form instead of plaintext passwords,
 * use the {@see BasicHashAuthenticationMethod} class instead.
 *
 * @internal
 *   This is here mostly for testing and completeness purposes;
 *   whatever HTTP/REST/PSR-7 library you're using,
 *   it can probably do this better.
 */
class BasicAuthenticationMethod implements AuthenticationMethod
{

    const HEADER = 'Authorization';

    public function authenticate(RequestInfo $request, string $apiClientId, string $apiClientKey): array
    {
        return [self::HEADER => 'Basic ' . base64_encode($apiClientId . ':' . $apiClientKey)];
    }

    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        [$username, $password] = $this->extractAuthenticationData($request);

        $knownPassword = $keys[$username];

        if (!hash_equals($knownPassword, $password)) {
            throw new InvalidAuthenticationException('auth password mismatch');
        }
    }

    public function getClientId(RequestInfo $request): string
    {
        return $this->extractAuthenticationData($request)[0];
    }

    /**
     * @param RequestInfo $request
     * @return string[]  [$username, $password]
     */
    protected function extractAuthenticationData(RequestInfo $request): array
    {
        $header = $request->getNonemptyHeaderValue(self::HEADER);

        if (strtolower(substr($header, 0, 6)) !== 'basic ') {
            throw new InvalidAuthenticationException('invalid ' . self::HEADER . ' header');
        }
        $header = trim(substr($header, 6), ' ');  // remove 'Basic ' prefix

        $decoded = base64_decode($header, true);
        if ($decoded === false || $decoded === null) {
            throw new CryptoErrorException('base64_decode failed');
        }

        if (strpos($decoded, ':') === false) {
            throw new InvalidAuthenticationException('invalid ' . self::HEADER . ' header payload');
        }

        [$username, $password] = explode(':', $decoded, 2);
        return [$username, $password];
    }

}
