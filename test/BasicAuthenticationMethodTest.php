<?php

namespace mle86\RequestAuthentication\Tests;

use GuzzleHttp\Psr7\Request;
use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\AuthenticationMethod\BasicAuthenticationMethod;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Tests\Helper\AuthenticationMethodTests;
use PHPUnit\Framework\TestCase;

class BasicAuthenticationMethodTest extends TestCase
{
    use AuthenticationMethodTests;

    protected function methodOutputDependsOnRequestData(): bool
    {
        // It's just a header containing the username and the password, it doesn't change if the input changes.
        return false;
    }

    protected function customKeyRepositoryEntries(): array { return [
        'U0000001' => 'topSecret:2018',
        // Needed for checkKnownValues().
        // base64_encode("U0000001:topSecret:2018") === "VTAwMDAwMDE6dG9wU2VjcmV0OjIwMTg="
    ]; }


    public function testGetInstance(): AuthenticationMethod
    {
        return new BasicAuthenticationMethod();
    }

    protected function otherTests(AuthenticationMethod $method): void
    {
        $this->checkKnownValues($method);
    }

    protected function checkKnownValues(AuthenticationMethod $method)
    {
        $request = new Request(
            'PUT', 'http://basic.test.localhost/foo',
            ['Content-Type: application/json; encoding=utf-8'],
            'SomeBody');

        $ri = RequestInfo::fromPsr7($request);

        [$username, $password] = [
            array_keys  ($this->customKeyRepositoryEntries())[0],
            array_values($this->customKeyRepositoryEntries())[0],
        ];

        $headers = $method->authenticate($ri, $username, $password);

        // Should add an 'Authorization' header and nothing else:
        $this->assertSame(['Authorization'], array_keys($headers));

        // The header should contain the correct base64 string:
        $regex = '/^Basic +' . preg_quote(base64_encode($username . ':' . $password), '/') . '\s*$/';
        $this->assertRegExp($regex, $headers['Authorization']);

        // And of course, the header should be accepted by BasicAuthenticationMethod itself:
        $this->checkValidResult($request, $headers, $method);
    }

}
