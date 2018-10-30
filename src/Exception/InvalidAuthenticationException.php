<?php

namespace mle86\RequestAuthentication\Exception;

/**
 * Thrown by {@see AuthenticationMethod::verify()}
 * if the input request contains incorrect or malformed request authentication data.
 */
class InvalidAuthenticationException extends \RuntimeException implements RequestAuthenticationException
{

}
