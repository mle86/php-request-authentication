<?php

namespace mle86\RequestAuthentication\RequestIdList;

use mle86\RequestAuthentication\Exception\DuplicateRequestIDException;

/**
 * Interface for Request ID Lists.
 *
 * A Request ID List
 * is a running list of already-seen request IDs.
 *
 * It can be used to ensure
 * that no two requests with the same request ID are processed,
 * e.g. to prevent replay attacks.
 */
interface RequestIdList
{

    /**
     * @param string $requestId
     * @return bool  Returns true if the Request ID is already contained in the list ({@see put()} will fail),
     *               returns false if the Request ID is not yet known.
     */
    public function contains(string $requestId): bool;

    /**
     * Stores one Request ID in the list.
     *
     * This only works with Request IDs which are _not yet_ contained within the list.
     *
     * @param string $requestId
     * @return void  Returns if the ID has been added to the list successfully.
     * @throws DuplicateRequestIDException  if the Request ID has been seen previously.
     */
    public function put(string $requestId): void;

}
