<?php

namespace mle86\RequestAuthentication\Tests\Helper;

use GuzzleHttp\Psr7\Request;
use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\KeyRepository\ArrayRepository;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;
use Psr\Http\Message\RequestInterface;

/** @internal This trait is used by {@see AuthenticationMethodTests}. */
trait AuthenticationMethodTestHelpers
{

    protected function buildRequest(array $override = [], bool $addDefaultHeaders = true): RequestInterface
    {
        $defaultHeaders = ($addDefaultHeaders) ? $this->defaultRequestHeaders() : [];

        $method  = $override['method']  ?? self::sampleMethod();
        $scheme  = $override['scheme']  ?? self::sampleScheme();
        $host    = $override['host']    ?? self::sampleHost();
        $path    = $override['path']    ?? self::samplePath();
        $headers = $override['headers'] ?? self::sampleHeaders();
        $body    = $override['body']    ?? self::sampleBody();
        $uri     = $override['uri']     ?? ($scheme . '://' . $host . $path);

        return new Request($method, $uri, $headers + $defaultHeaders, $body);
    }

    /**
     * Adds some headers to a request (without changing the existing instance),
     * then tests it against the known client IDs/keys (see {@see getTestingKeyRepository}).
     *
     * @param RequestInterface $request The request to test (after the $addHeaders have been added).
     * @param array $addHeaders         The headers to add. This is what {@see AuthenticationMethod::authenticate} returned.
     * @param AuthenticationMethod $method
     */
    protected function checkValidResult(RequestInterface $request, array $addHeaders, AuthenticationMethod $method): void
    {
        $authenticatedRequest = $this->applyHeaders($request, $addHeaders);
        $authenticatedRi      = RequestInfo::fromPsr7($authenticatedRequest);

        $method->verify($authenticatedRi, $this->getTestingKeyRepository());
    }

    /**
     * Takes an array of added headers (as returned by {@see AuthenticationMethod::authenticate}
     * and adds them to an existing PSR-7 request.
     *
     * @param RequestInterface $request
     * @param array $addHeaders  [headerName => headerValue, …]
     * @param bool $replace  If this is true (default), existing headers will be overwritten.
     * @return RequestInterface  Returns in instance with added headers. (It will never return the same instance.)
     */
    protected function applyHeaders(RequestInterface $request, array $addHeaders, bool $replace = true): RequestInterface
    {
        $authenticatedRequest = clone $request;

        foreach ($addHeaders as $name => $value) {
            if ($replace) {
                // add the header, overwriting it if it already exists
                $authenticatedRequest = $authenticatedRequest->withHeader($name, $value);
            } else {
                // just add the header, possibly creating a repeated header
                $authenticatedRequest = $authenticatedRequest->withAddedHeader($name, $value);
            }
        }

        return $authenticatedRequest;
    }

    /**
     * By default, this returns an {@see ArrayRepository}
     * that contains only the two class defaults ({@see sampleClientId} and {@see otherClientId} and their keys).
     *
     * Don't forget to include those two keys in your custom repository if you override this,
     * or {@see testSampleRequest} and {@see testMismatchOnDifferentInput} won't work correctly!
     *
     * If you just want to add some custom entries to the repository for your test class or alter some of the default entries,
     * override {@see customKeyRepositoryEntries} instead.
     *
     * @return KeyRepository
     */
    protected function getTestingKeyRepository(): KeyRepository
    {
        return new ArrayRepository($this->customKeyRepositoryEntries() + [
            self::sampleClientId() => self::sampleClientKey(),
            self::otherClientId()  => self::otherClientKey(),
        ]);
    }

    /**
     * Tries to add a repeated header (with random value) to the request
     * and expects the verification to fail (because the repeated header should affect the signature).
     *
     * Also tries to add a repeated header (with SAME value) to the request
     * and expects the verification to fail (RequestInfo concatenates repeated headers).
     *
     * This is basically an extra test method but it doesn't work with every AuthenticationMethod,
     * so you'll have to call it manually from your {@see otherTests()} method, possibly more than once.
     *
     * @param AuthenticationMethod $method
     * @param RequestInterface $request  The request to test. Should already have valid authentication headers added.
     * @param string $headerName         The HTTP header name to repeat.
     */
    protected function checkRepeatedPayloadHeader(AuthenticationMethod $method, RequestInterface $request, string $headerName): void
    {
        // If the signature gets repeated with a random value, the signature should change:
        $randomValue = 'RANDOM-HEADER-VALUE-' . random_int(1, 999999);
        $invalidRequest = $request->withAddedHeader($headerName, $randomValue);
        $this->assertException(InvalidAuthenticationException::class, function() use($invalidRequest, $method) {
            $this->checkValidResult($invalidRequest, [], $method);
        });

        // If a payload header gets repeated with the original value, the signature should also change:
        $invalidRequest = $request->withAddedHeader($headerName, $request->getHeader($headerName));
        $this->assertException(InvalidAuthenticationException::class, function() use($invalidRequest, $method) {
            $this->checkValidResult($invalidRequest, [], $method);
        });
    }

}
