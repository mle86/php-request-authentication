<?php

namespace mle86\RequestAuthentication;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\AuthenticationMethod\Feature\UsesRequestID;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\CryptoErrorException;
use mle86\RequestAuthentication\Exception\DuplicateRequestIDException;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;
use mle86\RequestAuthentication\RequestIdList\RequestIdList;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Wraps an {@see AuthenticationMethod} instance to verify inbound request authentication data.
 *
 *  - Can be used to verify authentication data in any PSR-7 {@see RequestInterface}
 *    with the {@see verify()} method.
 *  - Can be used to verify authentication data in any Symfony HttpFoundation {@see Request}
 *    with the {@see verifySymfonyRequest()} method.
 */
class RequestVerifier
{

    /** @var AuthenticationMethod */
    private $method;
    /** @var KeyRepository */
    private $keys;
    /** @var RequestIdList|null */
    private $requestIdList;

    public function __construct(AuthenticationMethod $method, KeyRepository $keys)
    {
        $this->method = $method;
        $this->keys   = $keys;
    }

    /**
     * Adds a {@see RequestIdList} instance to this RequestVerifier
     * which will be used to ensure Request ID Uniqueness
     * for all valid inbound requests.
     *
     * @param RequestIdList|null $requestIdList
     * @return self
     */
    public function withRequestIdList(?RequestIdList $requestIdList): self
    {
        $this->requestIdList = $requestIdList;
        return $this;
    }


    /**
     * Takes a PSR-7 RequestInterface instance
     * and checks the contained authentication token data.
     *
     * SIDE EFFECT: This will cause a {@see StreamInterface::rewind()} call
     *  on {@see RequestInterface::getBody()}.
     *
     * @param RequestInterface $request  The request to verify. The instance won't be modified.
     * @return string  Returns the client identification string (from {@see AuthenticationMethod::getClientId()}) on success.
     * @throws MissingAuthenticationHeaderException  on missing or empty authentication header(s).
     * @throws InvalidAuthenticationException  on incorrect authentication header(s).
     * @throws CryptoErrorException  if there was a problem with a low-level cryptographic function.
     * @throws DuplicateRequestIDException  if the request was valid but contained an already-seen Request ID (requires {@see withRequestIdList}).
     */
    public function verify(RequestInterface $request): string
    {
        return $this->verifyRequestInfo(RequestInfo::fromPsr7($request));
    }

    /**
     * Takes a Symfony HttpFoundation Request instance
     * and checks the contained authentication token data.
     *
     * @param Request $request  The request to verify. The instance won't be modified.
     * @return string  Returns the client identification string (from {@see AuthenticationMethod::getClientId()}) on success.
     * @throws MissingAuthenticationHeaderException  on missing or empty authentication header(s).
     * @throws InvalidAuthenticationException  on incorrect authentication header(s).
     * @throws CryptoErrorException  if there was a problem with a low-level cryptographic function.
     * @throws DuplicateRequestIDException  if the request was valid but contained an already-seen Request ID (requires {@see withRequestIdList}).
     */
    public function verifySymfonyRequest(Request $request): string
    {
        return $this->verifyRequestInfo(RequestInfo::fromSymfonyRequest($request));
    }

    /**
     * Reads the PHP globals (`$_SERVER` and `php://stdin`)
     * to read the current request (using {@see RequestInfo::fromGlobals})
     * and checks the contained authentication token data.
     *
     * SIDE EFFECT: This will open, read, rewind, and close `php://stdin`.
     *
     * @return string  Returns the client identification string (from {@see AuthenticationMethod::getClientId()}) on success.
     * @throws MissingAuthenticationHeaderException  on missing or empty authentication header(s).
     * @throws InvalidAuthenticationException  on incorrect authentication header(s).
     * @throws CryptoErrorException  if there was a problem with a low-level cryptographic function.
     * @throws DuplicateRequestIDException  if the request was valid but contained an already-seen Request ID (requires {@see withRequestIdList}).
     */
    public function verifyGlobals(): string
    {
        return $this->verifyRequestInfo(RequestInfo::fromGlobals());
    }

    /**
     * Returns a GuzzleHttp middleware handler
     * that will verify authentication data in all requests
     * according to the constructor settings.
     *
     * If any requests have no or incorrect authentication data,
     * a {@see MissingAuthenticationHeaderException}/{@see InvalidAuthenticationException} exception will be raised.
     *
     * @see HandlerStack::push()  can be used to add this RequestVerifier instance to a middleware handler stack.
     *
     * @param callable $handler
     * @return \Closure
     */
    public function __invoke(callable $handler): \Closure
    {
        return function(RequestInterface $request, array $options) use($handler) {
            $this->verify($request);
            return $handler($request, $options);
        };
    }


    private function verifyRequestInfo(RequestInfo $ri): string
    {
        $this->method->verify($ri, $this->keys);

        $clientId = $this->method->getClientId($ri);

        if ($this->requestIdList && $this->method instanceof UsesRequestID) {
            $this->requestIdList->put($this->method->getRequestId($ri));
        }

        return $clientId;
    }

}
