<?php

declare(strict_types=1);

namespace mle86\RequestAuthentication\KeyRepository;

/**
 * A client key repository that contains exactly one client key.
 */
class SingleKeyRepository extends KeyRepository
{

    private $clientId;
    private $clientKey;

    public function __construct($clientId, string $clientKey)
    {
        self::validateClientId($clientId);
        self::validateClientKey($clientKey);

        $this->clientId  = $clientId;
        $this->clientKey = $clientKey;
    }

    public function offsetExists($clientId): bool
    {
        return ($clientId === $this->clientId);
    }

    public function offsetGet($clientId): string
    {
        $this->requireClientId($clientId);
        return $this->clientKey;
    }

}
