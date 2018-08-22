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
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
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
class PublicKeyMethod
    implements AuthenticationMethod, UsesRequestID
{
    use HexRequestIDTrait;
    use DefaultDataTrait;

    const CLIENT_ID_HEADER  = 'X-API-Client';
    const SIGNATURE_HEADER  = 'X-API-Signature';

    const ADD_REQUEST_ID_HEADER_IF_MISSING = true;

    private const USE_HEADERS_FOR_SIGNATURE = [self::CLIENT_ID_HEADER, self::DEFAULT_REQUEST_ID_HEADER];


    protected function getSigner(string $api_secret_key): Signer
    {
        return new HaliteSigner(new HaliteSigningPrivateKey($api_secret_key));
    }

    protected function getVerifier(string $api_public_key): Verifier
    {
        return new HaliteVerifier(new HaliteSigningPublicKey($api_public_key));
    }


    public function authenticate(RequestInfo $request, string $api_client_id, string $api_secret_key): array
    {
        $output_headers = [
            self::CLIENT_ID_HEADER => $api_client_id,
        ];

        if (self::ADD_REQUEST_ID_HEADER_IF_MISSING && !$request->hasHeader(self::DEFAULT_REQUEST_ID_HEADER)) {
            $output_headers[self::DEFAULT_REQUEST_ID_HEADER] = $this->generateRequestId();
        }

        $signable_message = self::signableRequestData($request, self::USE_HEADERS_FOR_SIGNATURE, $output_headers);
        $signature        = $this->getSigner($api_secret_key)->sign($signable_message);
        $output_headers[self::SIGNATURE_HEADER] = $signature;

        return $output_headers;
    }

    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        $client_id  = $this->getClientId($request);
        $request_id = $request->getNonemptyHeaderValue(self::DEFAULT_REQUEST_ID_HEADER);
        $signature  = $request->getNonemptyHeaderValue(self::SIGNATURE_HEADER);

        self::validateRequestId($request_id);

        $signable_message = self::signableRequestData($request, self::USE_HEADERS_FOR_SIGNATURE);
        $public_key       = $keys[$client_id];
        $verifier         = $this->getVerifier($public_key);
        $verifier->verify($signable_message, $signature);
    }

    public function getClientId(RequestInfo $request): string
    {
        return $request->getNonemptyHeaderValue(self::CLIENT_ID_HEADER);
    }

}
