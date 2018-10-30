<?php

namespace mle86\RequestAuthentication;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\CryptoErrorException;
use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

/**
 * Contains a list of other {@see AuthenticationMethod} instances
 * which will be used to verify requests.
 *
 * This is useful if your API has several acceptable authentication methods
 * and you want to support them all with a single {@see verify()} call.
 *
 * This class itself implements the {@see AuthenticationMethod} interface,
 * so it can be used in place of single instances everywhere.
 *
 * Instances can be used for authentication:
 * the {@see authenticate()} call will always be delegated
 * to the _first instance_ in the stack.
 */
class MethodStack implements AuthenticationMethod
{

    /** @var AuthenticationMethod[] */
    private $methods;

    private $lastRequest;
    private $lastMethod;

    /**
     * @param AuthenticationMethod[]|string[]|iterable  A list of {@see AuthenticationMethod} instances or class names.
     *                                                  Class names will be instantiated (which requires them to have a
     *                                                  public constructor without required arguments).
     *                                                  The list may _not_ be empty.
     */
    public function __construct(iterable $methods)
    {
        if ($methods === [] || empty($methods)) {
            throw new InvalidArgumentException('$methods cannot be empty');
        }

        foreach ($methods as &$method) {
            if (is_object($method) && $method instanceof AuthenticationMethod) {
                // okay, keep instance
            } elseif (is_string($method) && class_exists($method) && is_subclass_of($method, AuthenticationMethod::class, true)) {
                // is fqdn of method class, instantiate:
                $method = new $method();
            } else {
                throw new InvalidArgumentException('$methods must be array of AuthenticationMethod instances or class names');
            }
        }
        unset($method);

        $this->methods = $methods;
    }

    /**
     * Proxy for {@see AuthenticationMethod::authenticate()}
     * of the _first method_ in the stack.
     *
     * @param RequestInfo $request
     * @param string $apiClientId
     * @param string $apiSecretKey
     * @return array
     * @throws CryptoErrorException
     */
    public function authenticate(RequestInfo $request, string $apiClientId, string $apiSecretKey): array
    {
        $method = reset($this->methods);
        return $method->authenticate($request, $apiClientId, $apiSecretKey);
    }

    /**
     * Calls {@see AuthenticationMethod::verify()}
     * on all method instances in the stack (in their original order)
     * until one of them verifies the request.
     *
     * All {@see InvalidAuthenticationException}s/{@see MissingAuthenticationHeaderException}s/{@see CryptoErrorException}s
     * are ignored.
     *
     * If none of the method instances accept the input
     * and they all throw a {@see MissingAuthenticationHeaderException}s,
     * the first of them is re-thrown.
     * If none of the method instances accept the input
     * and at least one of them throws a {@see InvalidAuthenticationException} or {@see CryptoErrorException},
     * a new {@see InvalidAuthenticationException} is thrown.
     *
     * @param RequestInfo $request
     * @param KeyRepository $keys
     * @throws InvalidAuthenticationException  if none of the method instances in the stack accepted the request and at least one of them threw an {@see InvalidAuthenticationException}.
     * @throws InvalidAuthenticationException  if none of the method instances in the stack accepted the request and they all threw {@see MissingAuthenticationHeaderException}s.
     */
    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        $usedMethod = $this->applyStack(
            $this->methods,
            function(AuthenticationMethod $method) use($request, $keys) {
                $method->verify($request, $keys);
            }
        )[0];

        $this->lastRequest = $request;
        $this->lastMethod  = $usedMethod;
    }

    /**
     * Calls {@see AuthenticationMethod::getClientId()}
     * on all method instances in the stack
     * until one of them returns the client ID.
     *
     * All {@see InvalidAuthenticationException}s/{@see MissingAuthenticationHeaderException}s/{@see CryptoErrorException}s
     * are ignored.
     *
     * If none of the method instances accept the input,
     * an {@see InvalidAuthenticationException} is thrown.
     *
     * **⚠ NB:**
     *   It is only safe to call this method if {@see verify()} has been called before _and_
     *   if the last successful {@see verify()} call had the same request argument.
     *   Otherwise, the wrong method may be chosen which might return an incorrect client id.
     *   The {@see RequestVerifier} helper class does this correctly.
     *
     * @param RequestInfo $request
     * @return string
     * @throws InvalidAuthenticationException  if none of the method instances in the stack accepted the request.
     */
    public function getClientId(RequestInfo $request): string
    {
        /* This method is a bit tricky.
         *
         * While verify() looks at _all_ relevant headers,
         * the getClientId() implementation typically looks at one header only
         * and does minimal validation.
         *
         * So if there's different method classes with the same client id header name in the stack,
         * we might easily get the result from the wrong class.
         * This becomes a problem if the getClientId() does some more work with the header value
         * such as extracting the username from an encoded header (e.g. Basic authentication)
         * and does not throw an exception.
         *
         * This is why verify() remembers the last request and its associated method
         * which we'll re-use here.
         */

        $methods = $this->methods;
        if ($request === $this->lastRequest) {
            // we already know the correct method for this request, try it first:
            $methods = array_merge([$this->lastMethod], $methods);
        }

        return $this->applyStack(
            $methods,
            function(AuthenticationMethod $method) use($request): string {
                return $method->getClientId($request);
            }
        )[1];
    }

    /**
     * @param AuthenticationMethod[]|iterable $methods  The list of methods to try.
     * @param callable $callback                        The callback to execute. Will receive one {@see AuthenticationMethod} instance as its only argument.
     * @return array  Returns an array with two elements.
     *                The first element is the successful {@see AuthenticationMethod} instance,
     *                the second element is whatever the first successful callback returned (which might be void/null).
     * @throws InvalidAuthenticationException  if the callback worked with none of the method instances in the stack.
     * @throws MissingAuthenticationHeaderException  if the callback worked with none of the method instances in the stack.
     */
    private function applyStack(iterable $methods, callable $callback): array
    {
        $first_mh_exception = null;
        $first_cr_exception = null;
        $first_ia_exception = null;

        foreach ($methods as $method) {
            try {
                return [$method, $callback($method)];

            } catch (InvalidAuthenticationException $e) {
                if (!$first_ia_exception) {
                    $first_ia_exception = $e;
                }
                // continue!
            } catch (MissingAuthenticationHeaderException $e) {
                if (!$first_mh_exception) {
                    $first_mh_exception = $e;
                }
                // continue!
            } catch (CryptoErrorException $e) {
                if (!$first_cr_exception) {
                    $first_cr_exception = $e;
                }
                // continue!
            }
        }

        $errmsg = 'no applicable authentication method in stack';
        if ($first_cr_exception || $first_ia_exception) {
            throw new InvalidAuthenticationException($errmsg, 0, $first_cr_exception ?? $first_ia_exception);
        }
        throw new MissingAuthenticationHeaderException($errmsg, 0, $first_mh_exception);
    }

    /**
     * @return AuthenticationMethod[]
     *   Returns the contained {@see AuthenticationMethod} instances in their original order.
     */
    public function getMethods(): array
    {
        return $this->methods;
    }

}
