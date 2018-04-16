<?php
namespace mle86\RequestAuthentication\Exception;

/**
 * Thrown by {@see AuthenticationMethod::verify()}
 * and by {@see RequestInfo}'s header getters
 * in case of a missing or empty header value
 * that should be present and non-empty.
 */
class MissingAuthenticationHeaderException
    extends \RuntimeException
    implements RequestAuthenticationException
{

}
