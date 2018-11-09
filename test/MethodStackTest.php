<?php

declare(strict_types=1);

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
use mle86\RequestAuthentication\MethodStack;
use mle86\RequestAuthentication\Tests\Helper\AssertException;
use mle86\RequestAuthentication\Tests\Helper\AuthenticationMethodTestConfiguration;
use mle86\RequestAuthentication\Tests\Helper\AuthenticationMethodTestDefaults;
use mle86\RequestAuthentication\Tests\Helper\AuthenticationMethodTestHelpers;
use mle86\RequestAuthentication\Tests\Helper\TestMethodA;
use mle86\RequestAuthentication\Tests\Helper\TestMethodB;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

class MethodStackTest extends TestCase
{
    use AuthenticationMethodTestHelpers;
    use AuthenticationMethodTestDefaults;
    use AuthenticationMethodTestConfiguration;
    use AssertException;

    public function testConstructor(): MethodStack
    {
        $initializer = [new TestMethodA(), new TestMethodA()];

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
        $initializer = [new TestMethodA(), TestMethodB::class];

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
    public function testAuthenticate(MethodStack $ab): void
    {
        $emptyRequest = $this->buildRequest();

        $authHeaders = $ab->authenticate(RequestInfo::fromPsr7($emptyRequest), 'C0', 'CS');

        // The first method should have added its headers and should therefore now consider the complete request valid:
        $this->checkValidResult($emptyRequest, $authHeaders, new TestMethodA());

        // The second method should NOT have added its headers and should therefore still consider the complete request invalid:
        $this->assertException(InvalidAuthenticationException::class,
            function() use($emptyRequest, $authHeaders) {
                $this->checkValidResult($emptyRequest, $authHeaders, new TestMethodB());
            });
    }

    /**
     * @depends testInstantiation
     */
    public function testVerify(MethodStack $ab): void
    {
        $emptyRequest = $this->buildRequest();

        $auth_a_headers = (new TestMethodA())->authenticate(RequestInfo::fromPsr7($emptyRequest), 'C0', 'CS');
        $auth_b_headers = (new TestMethodB())->authenticate(RequestInfo::fromPsr7($emptyRequest), 'C0', 'CS');

        // Both must be accepted:
        $this->checkValidResult($emptyRequest, $auth_a_headers, $ab);
        $this->checkValidResult($emptyRequest, $auth_b_headers, $ab);

        // Empty requests can never match.
        $this->assertException(MissingAuthenticationHeaderException::class,
            function() use($emptyRequest, $ab) {
                $this->checkValidResult($emptyRequest, [], $ab);
            });

        // Now we'll build a request that has the headers for both classes, but incorrect values.
        // This should result in an InvalidAuthenticationException internally, and we also expect that class to be thrown.
        $failHeaders = [
            TestMethodA::CLIENT_HEADER    => '?',
            TestMethodA::SIGNATURE_HEADER => '-3.3',
        ];
        $this->assertException(InvalidAuthenticationException::class,
            function() use($emptyRequest, $failHeaders, $ab) {
                $this->checkValidResult($emptyRequest, $failHeaders, $ab);
            });
    }

    /**
     * @depends testInstantiation
     * @depends testVerify
     */
    public function testGetClientId(MethodStack $ab): void
    {
        $baseRequest = $this->buildRequest();

        $assertClientId = function(MethodStack $stack, array $addHeaders, string $expectedClientId) use($baseRequest): void {
            $authenticatedRequest = $this->applyHeaders($baseRequest, $addHeaders);
            $ri = RequestInfo::fromPsr7($authenticatedRequest);

            // MethodStack::getClientId() promises correct results only if verify() is called before (with same request instance)
            $stack->verify($ri, $this->getTestingKeyRepository());

            $this->assertSame(
                $expectedClientId,
                $stack->getClientId($ri));
        };

        // Both method classes use the same client id header, but one of them adds a prefix to the value.
        // To make sure the stack is giving us the correct result, we'll have another stack with the entries' order reversed:
        $ba = new MethodStack([
            $ab->getMethods()[1],
            $ab->getMethods()[0],
        ]);

        $auth_a_headers = (new TestMethodA())->authenticate(RequestInfo::fromPsr7($baseRequest), 'C.A', 'CS');
        $auth_b_headers = (new TestMethodB())->authenticate(RequestInfo::fromPsr7($baseRequest), 'C.B', 'CS');

        $assertClientId($ab, $auth_a_headers, 'C.A');
        $assertClientId($ba, $auth_a_headers, 'C.A');

        $assertClientId($ab, $auth_b_headers, 'C.B');
        $assertClientId($ba, $auth_b_headers, 'C.B');
    }

}
