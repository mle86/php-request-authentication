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
