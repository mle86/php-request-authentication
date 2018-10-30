<?php

namespace mle86\RequestAuthentication\Exception;

/**
 * Thrown by {@see AuthenticationMethod} implementations
 * if a low-level cryptographic function fails unexpectedly.
 *
 * (If it was a hashing function such as {@see hash_hmac},
 *  the more specific {@see HashErrorException} is thrown instead.)
 */
class CryptoErrorException extends \UnexpectedValueException implements RequestAuthenticationException
{

}
