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
class ArrayRepository extends KeyRepository
{

    private $keys;

    public function __construct(array $keys)
    {
        foreach ($keys as $clientId => $clientKey) {
            self::validateClientId($clientId);
            self::validateClientKey($clientKey);
        }

        $this->keys = $keys;
    }


    public function offsetExists($clientId): bool
    {
        return isset($this->keys[$clientId]);
    }

    public function offsetGet($clientId): string
    {
        $this->requireClientId($clientId);
        return $this->keys[$clientId];
    }

}
