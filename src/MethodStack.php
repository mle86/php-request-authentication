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
 */
class MethodStack
    implements AuthenticationMethod
{

    /** @var AuthenticationMethod[] */
    private $methods;

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
                $method = new $method ();
            } else {
                throw new InvalidArgumentException('$methods must be array of AuthenticationMethod instances or class names');
            }
        }
        unset($method);

        $this->methods = $methods;
    }

    /**
     * Proxy for {@see AuthenticationMethod::authenticate()}
     * of the first method in the stack.
     *
     * @param RequestInfo $request
     * @param string $api_client_id
     * @param string $api_secret_key
     * @return array
     * @throws CryptoErrorException
     */
    public function authenticate(RequestInfo $request, string $api_client_id, string $api_secret_key): array
    {
        $method = reset($this->methods);
        return $method->authenticate($request, $api_client_id, $api_secret_key);
    }

    /**
     * Calls {@see AuthenticationMethod::verify()}
     * on all method instances in the stack (in their original order)
     * until one of them verifies the request.
     *
     * All {@see InvalidAuthenticationException}s/{@see MissingAuthenticationHeaderException}s/{@see CryptoErrorException}s
     * are ignored.
     *
     * If none of the method instances accept the input,
     * an {@see InvalidAuthenticationException} is thrown.
     *
     * @param RequestInfo $request
     * @param KeyRepository $keys
     * @throws InvalidAuthenticationException  if none of the method instances in the stack accepted the request.
     */
    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        $this->applyStack(
            $this->methods,
            function(AuthenticationMethod $method) use($request, $keys) {
                $method->verify($request, $keys);
            }
        );
    }

    /**
     * Calls {@see AuthenticationMethod::getClientId()}
     * on all method instances in the stack (in their original order)
     * until one of them returns the client ID.
     *
     * All {@see InvalidAuthenticationException}s/{@see MissingAuthenticationHeaderException}s/{@see CryptoErrorException}s
     * are ignored.
     *
     * If none of the method instances accept the input,
     * an {@see InvalidAuthenticationException} is thrown.
     *
     * @param RequestInfo $request
     * @return string
     * @throws InvalidAuthenticationException  if none of the method instances in the stack accepted the request.
     */
    public function getClientId(RequestInfo $request): string
    {
        return $this->applyStack(
            $methods,
            function(AuthenticationMethod $method) use($request): string {
                return $method->getClientId($request);
            }
        )[1];
    }

    /**
     * @param AuthenticationMethod[]|iterable $methods  The list of methods to try.
     * @param callable $callback  The callback to execute. Will receive one {@see AuthenticationMethod} instance as its only argument.
     * @return array  Returns an array with two elements.
     *                The first element is the successful {@see AuthenticationMethod} instance,
     *                the second element is whatever the first successful callback returned (which might be void/null).
     * @throws InvalidAuthenticationException  if the callback worked with none of the method instances in the stack.
     */
    private function applyStack(iterable $methods, callable $callback): array
    {
        $first_exception = null;

        foreach ($methods as $method) {
            try {
                return [$method, $callback($method)];
            } catch (InvalidAuthenticationException | MissingAuthenticationHeaderException | CryptoErrorException $e) {
                if (!$first_exception) {
                    $first_exception = $e;
                }
                // continue!
            }
        }

        throw new InvalidAuthenticationException('no applicable authentication method in stack', 0, $first_exception);
    }

    /**
     * @return AuthenticationMethod[]
     */
    public function getMethods(): array
    {
        return $this->methods;
    }

}
