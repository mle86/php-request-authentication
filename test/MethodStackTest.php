<?php
declare(strict_types=1);
namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\MethodStack;
use mle86\RequestAuthentication\Tests\Helper\AssertException;
use mle86\RequestAuthentication\Tests\Helper\AuthenticationMethodTestConfiguration;
use mle86\RequestAuthentication\Tests\Helper\AuthenticationMethodTestDefaults;
use mle86\RequestAuthentication\Tests\Helper\AuthenticationMethodTestHelpers;
use mle86\RequestAuthentication\Tests\Helper\TestMethodA;
use mle86\RequestAuthentication\Tests\Helper\TestMethodB;
use PHPUnit\Framework\TestCase;

class MethodStackTest
    extends TestCase
{
    use AuthenticationMethodTestHelpers;
    use AuthenticationMethodTestDefaults;
    use AuthenticationMethodTestConfiguration;
    use AssertException;

    public function testConstructor(): MethodStack
    {
        $initializer = [new TestMethodA, new TestMethodA];

        $stack = new MethodStack($initializer);
        $this->assertSame($initializer, $stack->getMethods());

        return $stack;
    }

    /**
     * @depends testConstructor
     * @return MethodStack  Returns a MethodStack of [TestMethodA, TestMethodB].
     */
    public function testInstantiation(): MethodStack
    {
        $initializer = [new TestMethodA, TestMethodB::class];

        $stack = new MethodStack($initializer);

        $this->assertCount(2, $stack->getMethods());

        // first argument was an instance which should not have been changed:
        $this->assertSame($initializer[0], $stack->getMethods()[0]);

        // second argument was a fqdn which should have been instantiated:
        $this->assertInstanceOf(TestMethodB::class, $stack->getMethods()[1]);

        return $stack;
    }

    /**
     * The test method receives a [TestMethodA, TestMethodB] stack,
     * so it should always add TestMethodA's headers.
     *
     * @depends testInstantiation
     */
    public function testAuthenticate(MethodStack $ab)
    {
        $empty_request = $this->buildRequest();

        $auth_headers = $ab->authenticate(RequestInfo::fromPsr7($empty_request), 'C0', 'CS');

        // The first method should have added its headers and should therefore now consider the complete request valid:
        $this->checkValidResult($empty_request, $auth_headers, new TestMethodA);

        // The second method should NOT have added its headers and should therefore still consider the complete request invalid:
        $this->assertException(InvalidAuthenticationException::class,
            function() use($empty_request, $auth_headers) {
                $this->checkValidResult($empty_request, $auth_headers, new TestMethodB);
            });
    }

    /**
     * @depends testInstantiation
     */
    public function testVerify(MethodStack $ab)
    {
        $empty_request = $this->buildRequest();

        $auth_a_headers = (new TestMethodA)->authenticate(RequestInfo::fromPsr7($empty_request), 'C0', 'CS');
        $auth_b_headers = (new TestMethodB)->authenticate(RequestInfo::fromPsr7($empty_request), 'C0', 'CS');

        // Both must be accepted:
        $this->checkValidResult($empty_request, $auth_a_headers, $ab);
        $this->checkValidResult($empty_request, $auth_b_headers, $ab);

        // Empty requests can never match.
        // This should cause a MissingAuthenticationHeaderException internally, but the stack should always emit an InvalidAuthenticationException:
        $this->assertException(InvalidAuthenticationException::class,
            function() use($empty_request, $ab) {
                $this->checkValidResult($empty_request, [], $ab);
            });

        // Now we'll build a request that has the headers for both classes, but incorrect values.
        // This should result in an InvalidAuthenticationException internally, and we also expect that class to be thrown.
        $fail_headers = [
            TestMethodA::CLIENT_HEADER    => '?',
            TestMethodA::SIGNATURE_HEADER => '-3.3',
        ];
        $this->assertException(InvalidAuthenticationException::class,
            function() use($empty_request, $fail_headers, $ab) {
                $this->checkValidResult($empty_request, $fail_headers, $ab);
            });
    }

}