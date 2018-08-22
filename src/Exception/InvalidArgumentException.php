<?php

namespace mle86\RequestAuthentication\Exception;

/**
 * Thrown in case of invalid input arguments,
 * same as the built-in {@see \InvalidArgumentException}.
 */
class InvalidArgumentException
    extends \InvalidArgumentException
    implements RequestAuthenticationException
{

}
