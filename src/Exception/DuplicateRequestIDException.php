<?php

namespace mle86\RequestAuthentication\Exception;

/**
 * Thrown (by {@see RequestIdList::put()})
 * when a duplicate/repeated Request ID is encountered.
 */
class DuplicateRequestIDException extends InvalidAuthenticationException
{

}
