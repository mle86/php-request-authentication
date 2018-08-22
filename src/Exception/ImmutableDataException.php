<?php

namespace mle86\RequestAuthentication\Exception;

/**
 * Thrown in case of a writing data access to an immutable structure,
 * e.g. trying to alter the values stored in a {@see KeyRepository}.
 */
class ImmutableDataException
    extends \LogicException
    implements RequestAuthenticationException
{

}
