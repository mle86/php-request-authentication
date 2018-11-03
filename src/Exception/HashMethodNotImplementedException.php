<?php

namespace mle86\RequestAuthentication\Exception;

class HashMethodNotImplementedException extends \UnexpectedValueException implements RequestAuthenticationException
{

    public static function withDefaultMessage(string $method, \Throwable $previous = null): self
    {
        return new self("hash method not implemented: {$method}", 0, $previous);
    }

}
