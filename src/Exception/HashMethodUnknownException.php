<?php

namespace mle86\RequestAuthentication\Exception;

class HashMethodUnknownException extends \UnexpectedValueException implements RequestAuthenticationException
{

    public static function withDefaultMessage(\Throwable $previous = null): self
    {
        return new self('unknown hash type', 0, $previous);
    }

}
