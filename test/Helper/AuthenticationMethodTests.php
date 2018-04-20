<?php
namespace mle86\RequestAuthentication\Tests\Helper;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\DTO\RequestInfo;
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

        $add_headers  = $method->authenticate($ri, self::sampleClientId(), self::sampleClientKey());
        $add_headers2 = $method->authenticate($ri, self::sampleClientId(), self::sampleClientKey());

        if ($add_headers !== $add_headers2) {
            $this->markTestSkipped(
                'Repeated authenticate() calls with same input produced different results, ' .
                'this makes this test and testMismatchOnDifferentInput unreliable.');
        }

        $this->checkValidResult($request, $add_headers, $method);

        return $add_headers;
    }

    /**
     * @depends testGetInstance
     * @depends testSampleRequest
     */
    public function testClientIdGetter(AuthenticationMethod $method, array $add_headers): void
    {
        if (!$this->methodOutputIncludesClientId()) {
            // cannot test with this method implementation
            return;
        }

        $original_request = $this->buildRequest();
        $original_ri      = RequestInfo::fromPsr7($original_request);

        // The original request contains no authentication data, so getClientId should fail:
        $this->assertException(MissingAuthenticationHeaderException::class, function() use($original_request, $method) {
            $this->checkValidResult($original_request, [], $method);
        });

        $authenticated_request = $this->applyHeaders($original_request, $add_headers);
        $authenticated_ri      = RequestInfo::fromPsr7($authenticated_request);

        // After adding all the headers, the client ID should be contained within the updated request:
        $this->assertSame(
            self::sampleClientId(),
            $method->getClientId($authenticated_ri));
    }

    /**
     * @dataProvider requestsFromDifferentInput
     * @depends testGetInstance
     * @depends testSampleRequest
     */
    public function testMismatchOnDifferentInput(RequestInterface $different_request, AuthenticationMethod $method, array $original_add_headers): void
    {
        $different_ri = RequestInfo::fromPsr7($different_request);
        $different_add_headers = $method->authenticate($different_ri, self::sampleClientId(), self::sampleClientKey());

        if ($this->methodOutputDependsOnRequestData()) {

            // Make sure the resulting headers (including the signature) differ from the very first sample request:
            $this->assertNotEquals($original_add_headers, $different_add_headers,
                "authenticate() added the exact same headers, but input data was different!");

            // Make sure the resulting headers (including the signature) also differ from all _other_ "different input" requests:
            static $seen_headers = [];
            $header_key = sha1(var_export($different_add_headers, true));
            $this->assertArrayNotHasKey($header_key, $seen_headers,
                "authenticate() result headers have been seen in an earlier modified input request!\n" .
                print_r($different_add_headers, true));
            $seen_headers[$header_key] = true;

        } else {
            // If the authentication output does not depend on the request data at all (i.e. constant authentication data),
            // the method output won't be different from testSampleRequest's output,
            // so we have to skip those assertions.
        }

        // The output should still be a valid signature for the changed input data:
        $this->checkValidResult($different_request, $different_add_headers, $method);
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
    public function testMismatchOnDifferentClient(array $override_client, AuthenticationMethod $method, array $original_add_headers): void
    {
        $request = $this->buildRequest();
        $ri = RequestInfo::fromPsr7($request);

        $client_id  = $override_client['id']  ?? self::sampleClientId();
        $client_key = $override_client['key'] ?? self::sampleClientKey();
        $different_add_headers = $method->authenticate($ri, $client_id, $client_key);

        // Make sure the changed client ID is contained in the output:
        if ($this->methodOutputIncludesClientId()) {
            $different_ri = RequestInfo::fromPsr7($this->applyHeaders($request, $different_add_headers));
            $this->assertSame(
                $client_id,
                $method->getClientId($different_ri));
        }

        // Make sure the resulting headers (including the signature) differ from the very first sample request:
        $this->assertNotEquals($original_add_headers, $different_add_headers,
            'authenticate() added the exact same headers, but client data was different!');

        // Make sure the resulting headers (including the signature) also differ from all _other_ "different client" requests:
        static $seen_headers = [];
        $header_key = sha1(var_export($different_add_headers, true));
        $this->assertArrayNotHasKey($header_key, $seen_headers,
            "authenticate() result headers have been seen in an earlier modified input request!\n" .
            print_r($different_add_headers, true));
        $seen_headers[$header_key] = true;
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
    public function testMissingHeaderValues($missing_value, AuthenticationMethod $method, array $add_headers): void
    {
        // build a basic sample request with known data and known client id/key:
        $request = $this->buildRequest();

        $relevant_headers = $this->authenticationHeaders() ?? array_keys($add_headers);

        // set every known authentication-relevant header...
        foreach ($relevant_headers as $header_name) {
            // ...to some "missing" value or remove it entirely:

            $incomplete_headers = $add_headers;
            if ($missing_value instanceof RemoveHeaderMarker) {
                unset($incomplete_headers[$header_name]);
            } else {
                $incomplete_headers[$header_name] = $missing_value;
            }

            $this->assertException(MissingAuthenticationHeaderException::class, function() use($request, $incomplete_headers, $method) {
                $this->checkValidResult($request, $incomplete_headers, $method);
            });
        }

        // and to be safe, set _all_ authentication-relevant headers to the same "missing" value or remove them all:
        if (count($relevant_headers) > 1) {
            $incomplete_headers = $add_headers;
            foreach ($relevant_headers as $header_name) {
                if ($missing_value instanceof RemoveHeaderMarker) {
                    unset($incomplete_headers[$header_name]);
                } else {
                    $incomplete_headers[$header_name] = $missing_value;
                }
            }

            $this->assertException(MissingAuthenticationHeaderException::class, function() use($request, $incomplete_headers, $method) {
                $this->checkValidResult($request, $incomplete_headers, $method);
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
    public function testInvalidHeaderValues($invalid_value, AuthenticationMethod $method, array $add_headers): void
    {
        // build a basic sample request with known data and known client id/key:
        $request = $this->buildRequest();

        $relevant_headers = $this->authenticationHeaders() ?? array_keys($add_headers);

        // set every known authentication-relevant header...
        foreach ($relevant_headers as $header_name) {
            // ...to some invalid value:
            $invalid_headers = [$header_name => $invalid_value] + $add_headers;  // !

            $this->assertException(InvalidAuthenticationException::class, function() use($request, $invalid_headers, $method) {
                $this->checkValidResult($request, $invalid_headers, $method);
            });
        }

        // and to be safe, set _all_ authentication-relevant headers to the same invalid value:
        if (count($relevant_headers) > 1) {
            $invalid_headers = $add_headers;
            foreach ($this->authenticationHeaders() as $header_name) {
                $invalid_headers[$header_name] = $invalid_value;
            }

            $this->assertException(InvalidAuthenticationException::class, function() use($request, $invalid_headers, $method) {
                $this->checkValidResult($request, $invalid_headers, $method);
            });
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
     */
    public function testOther(AuthenticationMethod $method, array $original_add_headers): void
    {
        $this->otherTests($method, $original_add_headers);
    }

}
