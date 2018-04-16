<?php
namespace mle86\RequestAuthentication\Exception;

/**
 * Thrown by {@see AuthenticationMethod} implementations
 * if a low-level hashing function fails unexpectedly.
 */
class HashErrorException
    extends CryptoErrorException
{

}
