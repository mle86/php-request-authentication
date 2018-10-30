<?php

declare(strict_types=1);

namespace mle86\RequestAuthentication\KeyRepository;

/**
 * A client key repository that contains exactly one client key.
 */
class SingleKeyRepository extends KeyRepository
{

    private $client_id;
    private $client_key;

    public function __construct($client_id, string $client_key)
    {
        self::validateClientId($client_id);
        self::validateClientKey($client_key);

        $this->client_id  = $client_id;
        $this->client_key = $client_key;
    }

    public function offsetExists($client_id): bool
    {
        return ($client_id === $this->client_id);
    }

    public function offsetGet($client_id): string
    {
        $this->requireClientId($client_id);
        return $this->client_key;
    }

}
