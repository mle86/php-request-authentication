<?php
namespace mle86\RequestAuthentication\Exception;

/**
 * Thrown by {@see AuthenticationMethod} implementations
 * if a low-level cryptographic function fails unexpectedly.
 */
class CryptoErrorException
    extends \UnexpectedValueException
    implements RequestAuthenticationException
{

}
