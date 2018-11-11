<?php

namespace mle86\RequestAuthentication\AuthenticationMethod;

use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\CryptoErrorException;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

/**
 * Authentication method used to sign or to verify requests.
 *
 * All implementation have two use cases:
 *
 *  - **Authentication:**
 *    Using the {@see authenticate()} method,
 *    outbound requests can be authenticated.
 *    The method calculates the authentication data for the request
 *    (such as a signature or a id+secret header)
 *    and returns it as additional headers to be added to the request before sending it.
 *
 *  - **Verification:**
 *    Using the {@see verify()} method,
 *    an inbound request's authentication header(s)
 *    can be tested against the rest of the request data (including the client ID)
 *    and the locally-known list of acceptable client IDs and their API secrets.
 *
 * There's also a {@see getClientId()} method that just extracts the API client identification from a request
 * in case you need it for authorization checking/rate limiting/logging.
 *
 * NB:
 *  It's not recommended to use the interface methods directly.
 *  Use the {@see RequestAuthenticator} and {@see RequestVerifier} helper classes instead.
 */
interface AuthenticationMethod
{

    /**
     * Calculates the authentication data for one request
     * based on its headers, http method/host/uri, and request body.
     *
     * @param RequestInfo $request
     * @param string $apiClientId  The API client's identification which will be included in the output headers.
     * @param string $apiSecretKey The client's secret key used to calculate the authentication token.
     * @return array  Returns an array of HTTP headers that must be added to the request before sending it: [headerName => headerValue, …]
     * @throws CryptoErrorException  if there was a problem with a low-level cryptographic function.
     */
    public function authenticate(RequestInfo $request, string $apiClientId, string $apiSecretKey): array;

    /**
     * Verifies one request's authentication token.
     *
     * This method extracts the client identification string from the request (using {@see getClientId}),
     * gets that client's key from the KeyRepository,
     * and verifies the request's authentication token
     * against that key and the request data.
     *
     * If the class implements the {@see UsesRequestID} interface,
     * this method must also ensure the existence and correct format
     * of the Request ID header
     * (but it need not ensure its uniqueness; that's a job for the {@see RequestIdList} classes).
     *
     * @param RequestInfo $request  The request to verify.
     * @param KeyRepository $keys   The client keys available for authentication.
     * @return void  on success.
     * @throws MissingAuthenticationHeaderException  on missing or empty authentication header(s).
     * @throws InvalidAuthenticationException  on incorrect authentication header(s).
     * @throws CryptoErrorException  if there was a problem with a low-level cryptographic function.
     */
    public function verify(RequestInfo $request, KeyRepository $keys): void;

    /**
     * Extracts the API client identification from an inbound request.
     *
     * NB: This method does NOT {@see verify} the request, it simply extracts the client identification.
     *  (The only validation it does is ensuring that the client identification header exists and is non-empty.)
     *
     * @param RequestInfo $request
     * @return string
     * @throws MissingAuthenticationHeaderException  on missing or empty authentication header(s).
     * @throws InvalidAuthenticationException  on incorrect authentication header(s).
     * @throws CryptoErrorException  if there was a problem with a low-level cryptographic function.
     */
    public function getClientId(RequestInfo $request): string;

}
