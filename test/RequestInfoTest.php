<?php

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
use mle86\RequestAuthentication\Tests\Helper\AssertException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * @backupGlobals enabled
 */
class RequestInfoTest
    extends TestCase
{
    use AssertException;

    private function buildRequest(array $override = []): RequestInfo
    {
        return new RequestInfo(
            $override['method']  ?? 'GET',
            $override['scheme']  ?? 'https',
            $override['host']    ?? 'www.domain.test:8080',
            $override['path']    ?? '/foo/bar?123',
            $override['body']    ?? 'input1=value1&input2=value2',
            $override['headers'] ?? [
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Content-Length' => '27',
                'X-Empty' => '',
            ]);
    }

    public function testCreateInstance(): RequestInfo
    {
        return $this->buildRequest();
    }

    /**
     * @depends testCreateInstance
     */
    public function testGetters(RequestInfo $ri): void
    {
        $this->assertSame('GET', $ri->getHttpMethod());
        $this->assertSame('https', $ri->getHttpScheme());
        $this->assertSame('www.domain.test:8080', $ri->getHttpHost());
        $this->assertSame('/foo/bar?123', $ri->getHttpPath());
        $this->assertSame('https://www.domain.test:8080/foo/bar?123', $ri->getUri());

        $this->assertTrue($ri->hasHeader('Content-Type'));
        $this->assertSame('application/x-www-form-urlencoded', $ri->getHeaderValue('Content-Type'));
        $this->assertSame('application/x-www-form-urlencoded', $ri->getNonemptyHeaderValue('Content-Type'));

        $this->assertTrue($ri->hasHeader('content-length'));
        $this->assertEquals(27, $ri->getHeaderValue('CONTENT-LENGTH'));
        $this->assertEquals(27, $ri->getNonemptyHeaderValue('CONTENT-LENGTH'));

        $this->assertEquals('', $ri->getHeaderValue('X-EMPTY'));
        $this->assertException(MissingAuthenticationHeaderException::class, function() use($ri) {
            $ri->getNonemptyHeaderValue('X-Empty');
        });

        $this->assertException(InvalidArgumentException::class, function() use($ri) {
            $ri->getHeaderValue('');
        });
    }

    /**
     * @depends testCreateInstance
     */
    public function testInvalidInput()
    {
        // Header values must be scalar.
        $this->assertException(InvalidArgumentException::class, function() {
            $headers = ['hdr1' => new \stdClass];
            $this->buildRequest(['headers' => $headers]);
        });

        $this->assertException(InvalidArgumentException::class, function() {
            $headers = ['repeated' => ['AAA', new \stdClass, 'BBB']];
            $this->buildRequest(['headers' => $headers]);
        });
    }

    /**
     * @depends testCreateInstance
     * @depends testGetters
     */
    public function testFromGlobals(): RequestInfo
    {
        $_SERVER['REQUEST_METHOD'] = 'Get';
        $_SERVER['REQUEST_SCHEME'] = 'HTTPS';
        $_SERVER['SERVER_NAME'] = 'www.domain.test';
        $_SERVER['SERVER_PORT'] = 8080;
        $_SERVER['REQUEST_URI'] = '/foo/bar?123';
        $_SERVER['HTTP_X_EMPTY'] = '';
        $_SERVER['HTTP_CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
        $_SERVER['HTTP_CONTENT_LENGTH'] = '27';

        $ri = RequestInfo::fromGlobals();

        $this->testGetters($ri);

        return $ri;
    }

    /**
     * @depends testCreateInstance
     * @depends testGetters
     */
    public function testFromSymfonyRequest(): RequestInfo
    {
        $sr = Request::create(
            'https://www.domain.test:8080/foo/bar?123',
            'GET',
            [],
            [],
            [],
            [
                'HTTP_X_EMPTY'        => '',
                'HTTP_CONTENT_TYPE'   => 'application/x-www-form-urlencoded',
                'HTTP_CONTENT_LENGTH' => '27',
            ],
            'input1=value1&input2=value2');

        $ri = RequestInfo::fromSymfonyRequest($sr);

        $this->testGetters($ri);

        return $ri;
    }

}
