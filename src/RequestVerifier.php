<?php
namespace mle86\RequestAuthentication;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\CryptoErrorException;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Wraps an {@see AuthenticationMethod} instance to verify inbound request authentication data.
 *
 *  - Can be used to verify authentication data in any PSR-7 {@see RequestInterface}
 *    with the {@see verify()} method.
 *  - Can be used to verify authentication data in any Symfony HttpFoundation {@see Request}
 *    with the {@see authenticateSymfonyRequest()} method.
 */
class RequestVerifier
{

    private $method;
    private $keys;

    public function __construct(AuthenticationMethod $method, KeyRepository $keys)
    {
        $this->method = $method;
        $this->keys   = $keys;
    }


    /**
     * Takes a PSR-7 RequestInterface instance
     * and checks the contained authentication token data.
     *
     * @param RequestInterface $request  The request to verify. The instance won't be modified.
     * @return void  on success.
     * @throws MissingAuthenticationHeaderException  on missing or empty authentication header(s).
     * @throws InvalidAuthenticationException  on incorrect authentication header(s).
     * @throws CryptoErrorException  if there was a problem with a low-level cryptographic function.
     */
    public function verify(RequestInterface $request): void
    {
        $ri = RequestInfo::fromPsr7($request);
        $this->method->verify($ri, $this->keys);
    }

    /**
     * Takes a Symfony HttpFounddation Request instance
     * and checks the contained authentication token data.
     *
     * @param Request $request  The request to verify. The instance won't be modified.
     * @return void  on success.
     * @throws MissingAuthenticationHeaderException  on missing or empty authentication header(s).
     * @throws InvalidAuthenticationException  on incorrect authentication header(s).
     * @throws CryptoErrorException  if there was a problem with a low-level cryptographic function.
     */
    public function verifySymfonyRequest(Request $request): void
    {
        $ri = RequestInfo::fromSymfonyRequest($request);
        $this->method->verify($ri, $this->keys);
    }

    /**
     * Returns a GuzzleHttp middleware handler
     * that will verify authentication data in all requests
     * according to the constructor settings.
     *
     * If any requests have no or incorrect authentication data,
     * a {@see MissingAuthenticationHeaderException}/{@see InvalidAuthenticationException} exception will be raised.
     *
     * @see HandlerStack::push()  can be used to add this RequestAuthenticator instance to a middleware handler stack.
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

}
