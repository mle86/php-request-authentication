<?php
namespace mle86\RequestAuthentication\AuthenticationMethod;

use mle86\RequestAuthentication\AuthenticationMethod\Feature\DefaultDataTrait;
use mle86\RequestAuthentication\AuthenticationMethod\Feature\HexRequestIDTrait;
use mle86\RequestAuthentication\AuthenticationMethod\Feature\UsesRequestID;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\HashErrorException;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

/**
 * Default authentication method
 * for basic hash authentication.
 *
 *  - Valid requests contain a `X-API-Client` HTTP header
 *    containing the client ID.
 *
 *  - Valid requests contain a `X-API-Token` HTTP header
 *    containing a SHA256 HMAC hash
 *    of the request body,
 *    the HTTP method and URI,
 *    the `Content-Type` header,
 *    and the used client ID.
 *    The client secret is used as the HMAC key.
 *    (See {@see calculateToken} and {@see DefaultDataTrait::signableRequestData} for more info.)
 *
 *  - Valid requests contain a `X-Request-ID` HTTP header
 *    containing a hexadecimal value (length: 32…100),
 *    e.g. some random SHA256 value.
 *    That value should NOT be calculated from the request data.
 *
 *  - The client secret is used both for signing and for verifying.
 *
 *  - The {@see authenticate} method will...
 *     - add a random `X-Request-ID` HTTP header (if there is none),
 *     - add the `X-API-Client` HTTP header,
 *     - add the `X-API-Token` HTTP header with the calculated authentication token.
 *
 *  - The {@see verify} method will...
 *     - check if the `X-Request-ID` header value is present, has the correct length, and is some hexadecimal value,
 *     - check if the `X-API-Client` header value is a client ID known in the supplied {@see KeyRepository},
 *     - check if the `X-API-Token` authentication token header value matches the request data and the client's secret.
 *
 * - The {@see verify} method **will NOT...**
 *     - check if the `X-Request-ID` header value is actually unique.
 */
class DefaultAuthenticationMethod
    implements AuthenticationMethod, UsesRequestID
{
    use HexRequestIDTrait;
    use DefaultDataTrait;

    const DEFAULT_CLIENT_ID_HEADER  = 'X-API-Client';
    const DEFAULT_AUTH_TOKEN_HEADER = 'X-API-Token';

    const ADD_REQUEST_ID_HEADER_IF_MISSING = true;

    const TOKEN_ALGO = 'sha256';

    public function authenticate(RequestInfo $request, string $api_client_id, string $api_secret_key): array
    {
        $output_headers = [
            self::DEFAULT_CLIENT_ID_HEADER => $api_client_id,
        ];

        if (self::ADD_REQUEST_ID_HEADER_IF_MISSING && !$request->hasHeader(self::DEFAULT_REQUEST_ID_HEADER)) {
            $output_headers[self::DEFAULT_REQUEST_ID_HEADER] = $this->generateRequestId();
        }

        $output_headers[self::DEFAULT_AUTH_TOKEN_HEADER] =
            self::calculateToken($request, $api_secret_key, $output_headers);

        return $output_headers;
    }

    private static function calculateToken(RequestInfo $request, string $api_secret_key, array $extra_headers = []): string
    {
        $use_headers = [self::DEFAULT_CLIENT_ID_HEADER, self::DEFAULT_REQUEST_ID_HEADER];
        $data = self::signableRequestData($request, $use_headers, $extra_headers);

        $token = hash_hmac(self::TOKEN_ALGO, $data, $api_secret_key);
        if ($token === '' || $token === null || $token === false || $token === '*') {
            throw new HashErrorException;
        }

        return $token;
    }

    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        $client_id  = $request->getNonemptyHeaderValue(self::DEFAULT_CLIENT_ID_HEADER);
        $request_id = $request->getNonemptyHeaderValue(self::DEFAULT_REQUEST_ID_HEADER);
        $auth_token = $request->getNonemptyHeaderValue(self::DEFAULT_AUTH_TOKEN_HEADER);

        self::validateRequestId($request_id);

        $client_key = $keys[$client_id];
        $expected_token = self::calculateToken($request, $client_key);

        if (!hash_equals($expected_token, $auth_token)) {
            throw new InvalidAuthenticationException('auth token mismatch');
        }
    }

}
