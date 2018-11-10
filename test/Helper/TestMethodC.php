<?php

namespace mle86\RequestAuthentication\Tests\Helper;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\AuthenticationMethod\Feature\HexRequestIDTrait;
use mle86\RequestAuthentication\AuthenticationMethod\Feature\UsesRequestID;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

/**
 * This AuthenticationMethod implementation
 * has a `X-Test-Signature` header with a random odd positive number between 1000..1999
 * and a `X-Test-Client` header with the client id.
 *
 * The client secret is not used.
 * The key repository is not used.
 *
 * It is very similar to {@see TestMethodA} and {@see TestMethodB}
 * which uses the same headers,
 * but this one expects the signature value to be even
 * and in a totally different range: 4000..4999.
 *
 * Besides the odd signature number, there's another difference:
 * it has a prefix in the client id header!
 *
 * Also it implements the {@see UsesRequestID} interface
 * to test {@see MethodStack::getRequestId()}.
 * In the request it adds a prefix to the request id
 * (which TestMethodB doesn't).
 */
class TestMethodC implements AuthenticationMethod, UsesRequestID
{
    use HexRequestIDTrait;

    const SIGNATURE_HEADER = TestMethodA::SIGNATURE_HEADER;
    const CLIENT_HEADER    = TestMethodA::CLIENT_HEADER;

    const CLIENT_PREFIX = TestMethodB::CLIENT_PREFIX;
    const REQUEST_ID_PREFIX = 'RIDPREFIX!';  // contains a "!" which won't pass TestMethodB::validateRequestId

    public function authenticate(RequestInfo $request, string $apiClientId, string $apiSecretKey): array
    {
        return [
            self::CLIENT_HEADER    => self::CLIENT_PREFIX . $apiClientId,
            self::SIGNATURE_HEADER => 2 * random_int(2000, 2499),  // 2500..2999 x2 = 4000..4998 (even)
            self::DEFAULT_REQUEST_ID_HEADER => self::REQUEST_ID_PREFIX . $this->generateRequestId(),
        ];
    }

    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        $this->getClientId($request);  // value required but not validated

        self::validateRequestId($this->getRequestId($request));

        $sig = $request->getNonemptyHeaderValue(self::SIGNATURE_HEADER);
        $isOddInteger = (
            (is_int($sig) || ctype_digit($sig)) &&
            $sig >= 4000 && $sig <= 4999 &&
            ($sig % 2) === 0);
        if (!$isOddInteger) {
            throw new InvalidAuthenticationException('invalid signature value');
        }
    }

    public function getClientId(RequestInfo $request): string
    {
        $header = $request->getNonemptyHeaderValue(self::CLIENT_HEADER);

        if (substr($header, 0, strlen(self::CLIENT_PREFIX)) !== self::CLIENT_PREFIX) {
            throw new InvalidAuthenticationException('client id header has incorrect prefix');
        }

        return substr($header, strlen(self::CLIENT_PREFIX));
    }

    public function getRequestId(RequestInfo $request): string
    {
        $rawRequestId = $request->getNonemptyHeaderValue(self::DEFAULT_REQUEST_ID_HEADER);

        $prefix    = self::REQUEST_ID_PREFIX;
        $prefixLen = strlen(self::REQUEST_ID_PREFIX);
        if (substr($rawRequestId, 0, $prefixLen) !== $prefix) {
            throw new InvalidAuthenticationException('request id head has incorrect prefix');
        }

        return substr($rawRequestId, $prefixLen);
    }

}
