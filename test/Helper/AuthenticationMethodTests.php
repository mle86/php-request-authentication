<?php

namespace mle86\RequestAuthentication\Tests\Helper;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\CryptoErrorException;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
use Psr\Http\Message\RequestInterface;

trait AuthenticationMethodTests
{
    use AuthenticationMethodTestConfiguration;
    use AuthenticationMethodTestHelpers;
    use AuthenticationMethodTestDefaults;
    use AuthenticationMethodTestProviders;
    use AssertException;


    abstract public function testGetInstance(): AuthenticationMethod;

    /**
     * Builds a sample request for {@see sampleClientId} authenticated with {@see sampleClientKey}.
     *
     * It also ensures that the generated request passes {@see AuthenticationMethod::verify()}
     * (via {@see checkValidResult}).
     *
     * @return array  It returns the extra headers returned by {@see AuthenticationMethod::authenticate()}.
     *
     * @depends testGetInstance
     */
    public function testSampleRequest(AuthenticationMethod $method): array
    {
        $request = $this->buildRequest();
        $ri = RequestInfo::fromPsr7($request);

        $addHeaders  = $method->authenticate($ri, self::sampleClientId(), self::sampleClientKey());
        $addHeaders2 = $method->authenticate($ri, self::sampleClientId(), self::sampleClientKey());

        if ($addHeaders !== $addHeaders2) {
            $this->markTestSkipped(
                'Repeated authenticate() calls with same input produced different results, ' .
                'this makes this test and testMismatchOnDifferentInput unreliable.');
        }

        $this->checkValidResult($request, $addHeaders, $method);

        return $addHeaders;
    }

    /**
     * @depends testGetInstance
     * @depends testSampleRequest
     */
    public function testClientIdGetter(AuthenticationMethod $method, array $addHeaders): void
    {
        if (!$this->methodOutputIncludesClientId()) {
            // cannot test with this method implementation
            return;
        }

        $originalRequest = $this->buildRequest();
        $originalRi      = RequestInfo::fromPsr7($originalRequest);

        // The original request contains no authentication data, so getClientId should fail:
        $this->assertException(MissingAuthenticationHeaderException::class, function() use($originalRequest, $method) {
            $this->checkValidResult($originalRequest, [], $method);
        });

        $authenticatedRequest = $this->applyHeaders($originalRequest, $addHeaders);
        $authenticatedRi      = RequestInfo::fromPsr7($authenticatedRequest);

        // After adding all the headers, the client ID should be contained within the updated request:
        $this->assertSame(
            self::sampleClientId(),
            $method->getClientId($authenticatedRi));
    }

    /**
     * @dataProvider requestsFromDifferentInput
     * @depends testGetInstance
     * @depends testSampleRequest
     */
    public function testMismatchOnDifferentInput(RequestInterface $differentRequest, AuthenticationMethod $method, array $originalAddHeaders): void
    {
        $differentRi = RequestInfo::fromPsr7($differentRequest);
        $differentAddHeaders = $method->authenticate($differentRi, self::sampleClientId(), self::sampleClientKey());

        if ($this->methodOutputDependsOnRequestData()) {

            // Make sure the resulting headers (including the signature) differ from the very first sample request:
            $this->assertNotEquals($originalAddHeaders, $differentAddHeaders,
                "authenticate() added the exact same headers, but input data was different!");

            // Make sure the resulting headers (including the signature) also differ from all _other_ "different input" requests:
            static $seenHeaders = [];
            $headerKey = sha1(var_export($differentAddHeaders, true));
            $this->assertArrayNotHasKey($headerKey, $seenHeaders,
                "authenticate() result headers have been seen in an earlier modified input request!\n" .
                print_r($differentAddHeaders, true));
            $seenHeaders[$headerKey] = true;

        } else {
            // If the authentication output does not depend on the request data at all (i.e. constant authentication data),
            // the method output won't be different from testSampleRequest's output,
            // so we have to skip those assertions.
        }

        // The output should still be a valid signature for the changed input data:
        $this->checkValidResult($differentRequest, $differentAddHeaders, $method);
    }

    /**
     * Changes the client key and re-calculates authentication data for the sample request.
     *
     * The result is expected to be different from {@see testSampleRequest}'s output
     * (it should contain a different signature/token/secret).
     *
     * (This is tried several times with various different client keys.
     *  The test method expects to see different output every time.
     *  This would be of course true by default if the AuthenticationMethod added something random to the request
     *  like a request ID or a timestamp, so make sure your method implementation does not do that in the context
     *  of this test method.)
     *
     * @dataProvider differentClientData
     * @dataProvider customDifferentClientData
     * @depends testGetInstance
     * @depends testSampleRequest
     */
    public function testMismatchOnDifferentClient(array $overrideClient, AuthenticationMethod $method, array $originalAddHeaders): void
    {
        $request = $this->buildRequest();
        $ri = RequestInfo::fromPsr7($request);

        $clientId  = $overrideClient['id']  ?? self::sampleClientId();
        $clientKey = $overrideClient['key'] ?? self::sampleClientKey();
        $differentAddHeaders = $method->authenticate($ri, $clientId, $clientKey);

        // Make sure the changed client ID is contained in the output:
        if ($this->methodOutputIncludesClientId()) {
            $differentRi = RequestInfo::fromPsr7($this->applyHeaders($request, $differentAddHeaders));
            $this->assertSame(
                $clientId,
                $method->getClientId($differentRi));
        }

        // Make sure the resulting headers (including the signature) differ from the very first sample request:
        $this->assertNotEquals($originalAddHeaders, $differentAddHeaders,
            'authenticate() added the exact same headers, but client data was different!');

        // Make sure the resulting headers (including the signature) also differ from all _other_ "different client" requests:
        static $seenHeaders = [];
        $headerKey = sha1(var_export($differentAddHeaders, true));
        $this->assertArrayNotHasKey($headerKey, $seenHeaders,
            "authenticate() result headers have been seen in an earlier modified input request!\n" .
            print_r($differentAddHeaders, true));
        $seenHeaders[$headerKey] = true;
    }

    /**
     * Authenticates sample requests with the _other_ known client keys
     * and makes sure verify() accepts them.
     *
     * We already created the authentication data for the {@see sampleClientId}
     * and fed it back to {@see AuthenticationMethod::verify} (in {@see testSampleRequest}).
     *
     * We also made sure that the {@see otherClientKey} produces different results
     * and is not valid with the same client id (in {@see testMismatchOnDifferentClient}).
     *
     * But we haven't actually tested the other client key(s) against verify().
     * That's what this method is for.
     * (It's not strictly necessary except in case of authentication methods
     * who support different kinds of client keys, like {@see BasicHashAuthenticationMethod} does).
     *
     * @dataProvider differentAuthenticationData
     * @dataProvider customDifferentAuthenticationData
     * @depends testGetInstance
     * @depends testSampleRequest
     * @depends testMismatchOnDifferentClient
     */
    public function testOtherClientAuthentications($clientId, string $clientKey, AuthenticationMethod $method): void
    {
        $request = $this->buildRequest();
        $ri = RequestInfo::fromPsr7($request);
        $addHeaders = $method->authenticate($ri, $clientId, $clientKey);
        $this->checkValidResult($request, $addHeaders, $method);
    }

    /**
     * Sets the method's known authentication headers to some "missing" value (NULL or the empty string) one by one,
     * then calls {@see AuthenticationMethod::verify} (via {@see checkValidResult})
     * and expects an {@see InvalidAuthenticationException}.
     *
     * Finally, it sets _all_ known authentication headers to some "missing" value
     * and tries again.
     *
     * @dataProvider missingAuthenticationHeaderValues
     * @depends testGetInstance
     * @depends testSampleRequest
     */
    public function testMissingHeaderValues($missingValue, AuthenticationMethod $method, array $addHeaders): void
    {
        // build a basic sample request with known data and known client id/key:
        $request = $this->buildRequest();

        $relevantHeaders = $this->authenticationHeaders() ?? array_keys($addHeaders);

        // set every known authentication-relevant header...
        foreach ($relevantHeaders as $headerName) {
            // ...to some "missing" value or remove it entirely:

            $incompleteHeaders = $addHeaders;
            if ($missingValue instanceof RemoveHeaderMarker) {
                unset($incompleteHeaders[$headerName]);
            } else {
                $incompleteHeaders[$headerName] = $missingValue;
            }

            $this->assertException(MissingAuthenticationHeaderException::class, function() use($request, $incompleteHeaders, $method) {
                $this->checkValidResult($request, $incompleteHeaders, $method);
            });
        }

        // and to be safe, set _all_ authentication-relevant headers to the same "missing" value or remove them all:
        if (count($relevantHeaders) > 1) {
            $incompleteHeaders = $addHeaders;
            foreach ($relevantHeaders as $headerName) {
                if ($missingValue instanceof RemoveHeaderMarker) {
                    unset($incompleteHeaders[$headerName]);
                } else {
                    $incompleteHeaders[$headerName] = $missingValue;
                }
            }

            $this->assertException(MissingAuthenticationHeaderException::class, function() use($request, $incompleteHeaders, $method) {
                $this->checkValidResult($request, $incompleteHeaders, $method);
            });
        }
    }

    /**
     * Sets the method's known authentication headers to some invalid value (such as `"*"`) one by one,
     * then calls {@see AuthenticationMethod::verify} (via {@see checkValidResult})
     * and expects an {@see InvalidAuthenticationException}.
     *
     * Finally, it sets _all_ known authentication headers to some invalid value
     * and tries again.
     *
     * @dataProvider invalidAuthenticationHeaderValues
     * @dataProvider customInvalidAuthenticationHeaderValues
     * @depends testGetInstance
     * @depends testSampleRequest
     */
    public function testInvalidHeaderValues($invalidValue, AuthenticationMethod $method, array $addHeaders): void
    {
        // build a basic sample request with known data and known client id/key:
        $request = $this->buildRequest();

        $relevantHeaders = $this->authenticationHeaders() ?? array_keys($addHeaders);

        // set every known authentication-relevant header...
        foreach ($relevantHeaders as $headerName) {
            // ...to some invalid value:
            $invalidHeaders = [$headerName => $invalidValue] + $addHeaders;  // !

            $this->assertException(InvalidAuthenticationException::class, function() use($request, $invalidHeaders, $method) {
                $this->checkValidResult($request, $invalidHeaders, $method);
            });
        }

        // and to be safe, set _all_ authentication-relevant headers to the same invalid value:
        if (count($relevantHeaders) > 1) {
            $invalidHeaders = $addHeaders;
            foreach ($this->authenticationHeaders() as $headerName) {
                $invalidHeaders[$headerName] = $invalidValue;
            }

            $this->assertException(InvalidAuthenticationException::class, function() use($request, $invalidHeaders, $method) {
                $this->checkValidResult($request, $invalidHeaders, $method);
            });
        }
    }

    /**
     * Builds a valid request with valid auth headers,
     * then adds those headers _again_ (repeated headers) --
     * at first header will be repeated one by one,
     * then all of them at once,
     * then one by one with garbage data,
     * then one by one no value.
     *
     * In all cases, the test method expects both {@see AuthenticationMethod::verify()} to fail
     * (either with an {@see InvalidAuthenticationException} or with a {@see CryptoErrorException}).
     *
     * @depends testGetInstance
     * @depends testSampleRequest
     */
    public function testRepeatedIdentificationHeader(AuthenticationMethod $method): void
    {
        $request = $this->buildRequest();
        $addHeaders = $method->authenticate(RequestInfo::fromPsr7($request), self::sampleClientId(), self::sampleClientKey());

        $fnExtraHeaders = function(array $extra) use($request, $addHeaders): RequestInterface {
            // first, apply the correct auth headers:
            $authenticatedRequest = $this->applyHeaders($request, $addHeaders);
            // ...then add the extra headers without replacing existing headers:
            return $this->applyHeaders($authenticatedRequest, $extra, false);
        };

        $fnExpectFailure = function(RequestInterface $request) use($method): void {
            $ri = RequestInfo::fromPsr7($request);
            $this->assertException(
                [InvalidAuthenticationException::class, CryptoErrorException::class],
                function() use($ri, $method) {
                    $method->verify($ri, $this->getTestingKeyRepository());
                }
            );
        };

        // Try to duplicate every authentication header. This should fail because RequestInfo concatenates repeated header values.
        foreach ($addHeaders as $name => $value) {
            $fnExpectFailure($fnExtraHeaders([$name => $value]));
        }

        // Try to duplicate ALL authentication headers at once. This should also fail.
        $fnExpectFailure($fnExtraHeaders($addHeaders));

        // Try to add a repeated garbage header. This should also fail.
        foreach ($addHeaders as $name => $value) {
            foreach ($this->invalidAuthenticationHeaderValues() as [$invalidValue]) {
                $fnExpectFailure($fnExtraHeaders([$name => $invalidValue]));
            }
        }

        // Try to add an extra EMPTY header. This should also fail because RequestInfo uses a join character, thereby invalidating the header value.
        foreach ($addHeaders as $name => $value) {
            $fnExpectFailure($fnExtraHeaders([$name => '']));
        }
    }


    /**
     * This test method depends on _all_ previous tests.
     *
     * @see otherTests
     *
     * @depends testGetInstance
     * @depends testSampleRequest
     * @depends testMismatchOnDifferentInput
     * @depends testMismatchOnDifferentClient
     * @depends testMissingHeaderValues
     * @depends testInvalidHeaderValues
     * @depends testRepeatedIdentificationHeader
     */
    public function testOther(AuthenticationMethod $method, array $originalAddHeaders): void
    {
        $this->otherTests($method, $originalAddHeaders);
    }

}
