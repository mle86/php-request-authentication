<?php

namespace mle86\RequestAuthentication\Exception;

/**
 * Thrown by {@see KeyRepository} implementations
 * if their key source is faulty --
 * for example if the key file is malformed or does not exist.
 */
class RepositorySourceException extends \UnexpectedValueException implements RequestAuthenticationException
{

}
