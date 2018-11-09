<?php

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\AuthenticationMethod\DefaultAuthenticationMethod;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
use mle86\RequestAuthentication\Tests\Helper\AuthenticationMethodTests;
use mle86\RequestAuthentication\Tests\Helper\RemoveHeaderMarker;
use mle86\RequestAuthentication\Tests\Helper\RunID;
use PHPUnit\Framework\TestCase;

class DefaultAuthenticationMethodTest extends TestCase
{
    use AuthenticationMethodTests;
    use RunID;

    public function testGetInstance(): AuthenticationMethod
    {
        return new DefaultAuthenticationMethod();
    }

    protected function defaultRequestHeaders(): array { return [
        // We want all of our test requests to carry the exact same request id, so we'll add it manually before calling authenticate():
        DefaultAuthenticationMethod::DEFAULT_REQUEST_ID_HEADER => self::runId(),
    ]; }

    public function customDifferentClientData(): array { return [
        /* The DefaultAuthenticationMethod includes the client ID in the hash data,
         * so we can assume that changing the client ID (and nothing else)
         * leads to different authenticate() output:  */
        [['id' => self::otherClientId()]],
        [['key' => self::otherClientKey(), 'id' => self::otherClientId()]],
    ]; }


    protected function otherTests(AuthenticationMethod $method, array $originalAddHeaders): void
    {
        $this->checkMissingRequestId($method, $originalAddHeaders);
        $this->checkModifiedRequestId($method, $originalAddHeaders);

        $this->checkRepeatedPayloadHeader($method, $this->applyHeaders($this->buildRequest(), $originalAddHeaders),
            'Content-Type');
    }

    /**
     * Not all values in {@see AuthenticationMethodTests::invalidAuthenticationHeaderValues()}
     * are suitable to test the `X-Request-ID` header,
     * because some of them actually look pretty valid for that header...
     * So we'll test that header manually in {@see checkMissingRequestId()} and {@see checkModifiedRequestId()}.
     */
    protected function authenticationHeaders(): array { return [
        DefaultAuthenticationMethod::DEFAULT_AUTH_TOKEN_HEADER,
        DefaultAuthenticationMethod::DEFAULT_CLIENT_ID_HEADER,
    ]; }

    protected function checkMissingRequestId(AuthenticationMethod $method, array $originalAddHeaders): void
    {
        $request = $this->buildRequest();

        foreach ($this->missingAuthenticationHeaderValues() as [$missingValue]) {
            $incompleteRequest = ($missingValue instanceof RemoveHeaderMarker)
                ? $request->withoutHeader(DefaultAuthenticationMethod::DEFAULT_REQUEST_ID_HEADER)
                : $request->withHeader(DefaultAuthenticationMethod::DEFAULT_REQUEST_ID_HEADER, $missingValue);

            $incompleteHeaders = $originalAddHeaders;
            unset($incompleteHeaders[DefaultAuthenticationMethod::DEFAULT_REQUEST_ID_HEADER]);

            $this->assertException(MissingAuthenticationHeaderException::class, function() use($incompleteHeaders, $incompleteRequest, $method) {
                $this->checkValidResult($incompleteRequest, $incompleteHeaders, $method);
            });
        }
    }

    protected function checkModifiedRequestId(AuthenticationMethod $method, array $originalAddHeaders): void
    {
        $request = $this->buildRequest();

        $invalidValues = ['*', "\x00"];
        foreach ($invalidValues as $invalidValue) {
            $invalidHeaders = $originalAddHeaders;
            $invalidHeaders[DefaultAuthenticationMethod::DEFAULT_REQUEST_ID_HEADER] = $invalidValue;

            $this->assertException(InvalidAuthenticationException::class, function() use($invalidHeaders, $request, $method) {
                $this->checkValidResult($request, $invalidHeaders, $method);
            });
        }
    }

}
