<?php

declare(strict_types=1);

namespace mle86\RequestAuthentication\KeyRepository;

/**
 * A client key repository based on a simple PHP array.
 *
 * - The constructor's input array must be in the form
 *   `[clientId => clientKey, …]`.
 *
 * - Client IDs must be non-zero integers or non-empty strings.
 * - Client keys must be non-empty strings.
 */
class ArrayRepository
    extends KeyRepository
{

    private $keys;

    public function __construct(array $keys)
    {
        foreach ($keys as $client_id => $client_key) {
            self::validateClientId($client_id);
            self::validateClientKey($client_key);
        }

        $this->keys = $keys;
    }


    public function offsetExists($client_id): bool
    {
        return isset($this->keys[$client_id]);
    }

    public function offsetGet($client_id): string
    {
        $this->requireClientId($client_id);
        return $this->keys[$client_id];
    }

}
