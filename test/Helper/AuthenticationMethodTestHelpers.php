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

    protected function buildRequest(array $override = [], bool $add_default_headers = true): RequestInterface
    {
        $default_headers = ($add_default_headers) ? $this->defaultRequestHeaders() : [];

        $method  = $override['method']  ?? self::sampleMethod();
        $scheme  = $override['scheme']  ?? self::sampleScheme();
        $host    = $override['host']    ?? self::sampleHost();
        $path    = $override['path']    ?? self::samplePath();
        $headers = $override['headers'] ?? self::sampleHeaders();
        $body    = $override['body']    ?? self::sampleBody();
        $uri     = $override['uri']     ?? ($scheme . '://' . $host . $path);

        return new Request($method, $uri, $headers + $default_headers, $body);
    }

    /**
     * Adds some headers to a request (without changing the existing instance),
     * then tests it against the known client IDs/keys (see {@see getTestingKeyRepository}).
     *
     * @param RequestInterface $request  The request to test (after the $add_headers have been added).
     * @param array $add_headers  The headers to add. This is what {@see AuthenticationMethod::authenticate} returned.
     * @param AuthenticationMethod $method
     */
    protected function checkValidResult(RequestInterface $request, array $add_headers, AuthenticationMethod $method): void
    {
        $authenticated_request = $this->applyHeaders($request, $add_headers);
        $authenticated_ri      = RequestInfo::fromPsr7($authenticated_request);

        $method->verify($authenticated_ri, $this->getTestingKeyRepository());
    }

    /**
     * Takes an array of added headers (as returned by {@see AuthenticationMethod::authenticate}
     * and adds them to an existing PSR-7 request.
     *
     * @param RequestInterface $request
     * @param array $add_headers  [headerName => headerValue, …]
     * @param bool $replace  If this is true (default), existing headers will be overwritten.
     * @return RequestInterface  Returns in instance with added headers. (It will never return the same instance.)
     */
    protected function applyHeaders(RequestInterface $request, array $add_headers, bool $replace = true): RequestInterface
    {
        $authenticated_request = clone $request;

        foreach ($add_headers as $name => $value) {
            if ($replace) {
                // add the header, overwriting it if it already exists
                $authenticated_request = $authenticated_request->withHeader($name, $value);
            } else {
                // just add the header, possibly creating a repeated header
                $authenticated_request = $authenticated_request->withAddedHeader($name, $value);
            }
        }

        return $authenticated_request;
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
     * @param string $header_name  The HTTP header name to repeat.
     */
    protected function checkRepeatedPayloadHeader(AuthenticationMethod $method, RequestInterface $request, string $header_name): void
    {
        // If the signature gets repeated with a random value, the signature should change:
        $random_value = 'RANDOM-HEADER-VALUE-' . random_int(1, 999999);
        $invalid_request = $request->withAddedHeader($header_name, $random_value);
        $this->assertException(InvalidAuthenticationException::class, function() use($invalid_request, $method) {
            $this->checkValidResult($invalid_request, [], $method);
        });

        // If a payload header gets repeated with the original value, the signature should also change:
        $invalid_request = $request->withAddedHeader($header_name, $request->getHeader($header_name));
        $this->assertException(InvalidAuthenticationException::class, function() use($invalid_request, $method) {
            $this->checkValidResult($invalid_request, [], $method);
        });
    }

}
