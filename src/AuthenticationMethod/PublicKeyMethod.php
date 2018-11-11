<?php

namespace mle86\RequestAuthentication\AuthenticationMethod;

use mle86\RequestAuthentication\AuthenticationMethod\Feature\DefaultDataTrait;
use mle86\RequestAuthentication\AuthenticationMethod\Feature\HexRequestIDTrait;
use mle86\RequestAuthentication\AuthenticationMethod\Feature\UsesRequestID;
use mle86\RequestAuthentication\Crypto\Halite\HaliteSigner;
use mle86\RequestAuthentication\Crypto\Halite\HaliteSigningPublicKey;
use mle86\RequestAuthentication\Crypto\Halite\HaliteSigningPrivateKey;
use mle86\RequestAuthentication\Crypto\Halite\HaliteVerifier;
use mle86\RequestAuthentication\Crypto\Signer;
use mle86\RequestAuthentication\Crypto\Verifier;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

/**
 * Authentication method using public/private client keys.
 *
 * This method is similar to the {@see DefaultAuthenticationMethod}
 * in that it will add a random `X-Request-ID` header (if missing)
 * which will also be checked by the {@see verify()} method.
 *
 * It also has the client identification string in the `X-API-Client` header.
 *
 * It has however no `X-API-Token` header.
 * It has the `X-API-Signature` header instead
 * which contains a cryptographic signature
 * calculated using the client's private key
 * and verified using the client's public key.
 *
 * This means that the {@see KeyRepository} supplied to {@see verify()}
 * must return the client's public key.
 * The client's private key should not be stored on the server side at all.
 *
 * @see https://github.com/paragonie/halite  This method assumes that the paragonie/halite cryptographic library is available in your project.
 */
class PublicKeyMethod implements AuthenticationMethod, UsesRequestID
{
    use HexRequestIDTrait;
    use DefaultDataTrait;

    const CLIENT_ID_HEADER = 'X-API-Client';
    const SIGNATURE_HEADER = 'X-API-Signature';

    const ADD_REQUEST_ID_HEADER_IF_MISSING = true;

    private const USE_HEADERS_FOR_SIGNATURE = [self::CLIENT_ID_HEADER, self::DEFAULT_REQUEST_ID_HEADER];


    protected function getSigner(string $apiSecretKey): Signer
    {
        return new HaliteSigner(new HaliteSigningPrivateKey($apiSecretKey));
    }

    protected function getVerifier(string $apiPublicKey): Verifier
    {
        return new HaliteVerifier(new HaliteSigningPublicKey($apiPublicKey));
    }


    public function authenticate(RequestInfo $request, string $apiClientId, string $apiClientKey): array
    {
        $outputHeaders = [
            self::CLIENT_ID_HEADER => $apiClientId,
        ];

        if (self::ADD_REQUEST_ID_HEADER_IF_MISSING && !$request->hasHeader(self::DEFAULT_REQUEST_ID_HEADER)) {
            $outputHeaders[self::DEFAULT_REQUEST_ID_HEADER] = $this->generateRequestId();
        }

        $signableMessage = self::signableRequestData($request, self::USE_HEADERS_FOR_SIGNATURE, $outputHeaders);
        $signature       = $this->getSigner($apiClientKey)->sign($signableMessage);
        $outputHeaders[self::SIGNATURE_HEADER] = $signature;

        return $outputHeaders;
    }

    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        $clientId  = $this->getClientId($request);
        $requestId = $this->getRequestId($request);
        $signature  = $request->getNonemptyHeaderValue(self::SIGNATURE_HEADER);

        self::validateRequestId($requestId);

        $signableMessage = self::signableRequestData($request, self::USE_HEADERS_FOR_SIGNATURE);
        $publicKey       = $keys[$clientId];
        $verifier        = $this->getVerifier($publicKey);
        $verifier->verify($signableMessage, $signature);
    }

    public function getClientId(RequestInfo $request): string
    {
        return $request->getNonemptyHeaderValue(self::CLIENT_ID_HEADER);
    }

    public function getRequestId(RequestInfo $request): string
    {
        return $request->getNonemptyHeaderValue(self::DEFAULT_REQUEST_ID_HEADER);
    }

}
