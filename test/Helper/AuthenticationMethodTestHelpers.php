<?php
namespace mle86\RequestAuthentication\Tests\Helper;

use GuzzleHttp\Psr7\Request;
use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\DTO\RequestInfo;
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
     * @return RequestInterface  Returns in instance with added headers. (It will never return the same instance.)
     */
    protected function applyHeaders(RequestInterface $request, array $add_headers): RequestInterface
    {
        $authenticated_request = clone $request;

        foreach ($add_headers as $name => $value) {
            $authenticated_request = $authenticated_request->withHeader($name, $value);
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

}
