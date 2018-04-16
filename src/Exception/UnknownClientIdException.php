<?php
namespace mle86\RequestAuthentication\Exception;

/**
 * Thrown by {@see KeyRepository} implementations
 * in case of an unknown client ID.
 */
class UnknownClientIdException
    extends InvalidAuthenticationException
{

}
