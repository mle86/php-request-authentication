<?php

namespace mle86\RequestAuthentication\AuthenticationMethod\Feature;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;
use mle86\RequestAuthentication\AuthenticationMethod\DefaultAuthenticationMethod;

/**
 * An interface for {@see AuthenticationMethod} implementations
 * that support random request IDs.
 *
 * - The {@see AuthenticationMethod::verify()} method of implementing classes
 *   should verify that there is a request ID header and that it conforms to some agreed-upon validation rules,
 *   e.g. minimum/maximum length and hexadecimal charset.
 *
 * - The {@see AuthenticationMethod::verify()} method of implementing classes
 *   may check if the supplied request ID is actually unique,
 *   but it does not have to do so.
 *
 * - The {@see AuthenticationMethod::authenticate()} method of implementing classes
 *   may choose to reject requests without that header,
 *   to let them be sent unchanged (and later rejected by {@see verify()}),
 *   or to add a randomly-generated request ID itself.
 *
 * - Implementing {@see AuthenticationMethod} classes
 *   may allow setting a different request ID header name,
 *   but should always default to {@see UsesRequestID::DEFAULT_REQUEST_ID_HEADER}.
 *
 * @see DefaultAuthenticationMethod  implements this interface.
 *                                   The class does auto-generate missing request IDs in {@see authenticate}.
 *                                   The class does not check for unique request IDs in {@see verify}.
 */
interface UsesRequestID extends AuthenticationMethod
{

    const DEFAULT_REQUEST_ID_HEADER = 'X-Request-ID';

    const REQUEST_ID_MIN_LEN      = 32;
    const REQUEST_ID_MAX_LEN      = 100;

    const REQUEST_ID_RANDOM_BYTES = 10;
    const REQUEST_ID_HASH_ALGO    = 'sha256';

    /**
     * @return string  Generates one random request ID.
     * @see AuthenticationMethod::authenticate()  The main use case for this method -- to auto-generate missing request IDs.
     */
    public function generateRequestId(): string;

}
