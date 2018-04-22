<?php
namespace mle86\RequestAuthentication;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\CryptoErrorException;
use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

class MethodStack
    implements AuthenticationMethod
{

    /** @var AuthenticationMethod[] */
    private $methods;

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

    public function authenticate(RequestInfo $request, string $api_client_id, string $api_secret_key): array
    {
        $method = reset($this->methods);
        return $method->authenticate($request, $api_client_id, $api_secret_key);
    }

    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        $this->applyStack(
            function(AuthenticationMethod $method) use($request, $keys): void {
                $method->verify($request, $keys);
            }
        );
    }

    public function getClientId(RequestInfo $request): string
    {
        return $this->applyStack(
            function(AuthenticationMethod $method) use($request): string {
                return $method->getClientId($request);
            }
        );
    }

    private function applyStack(callable $callback)
    {
        $first_exception = null;

        foreach ($this->methods as $method) {
            try {
                return $callback($method);
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
