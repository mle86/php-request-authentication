<?php

declare(strict_types=1);

namespace mle86\RequestAuthentication\KeyRepository;

use mle86\RequestAuthentication\Exception\ImmutableDataException;
use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\Exception\UnknownClientIdException;

/**
 * A key repository can look up client API keys/secrets
 * by their client identification.
 *
 * They are needed by {@see AuthenticationMethod::verify()}
 * to look up the correct client API key/secret
 * for the client identification string
 * contained within the request.
 *
 * A basic implementation is the {@see ArrayRepository} which simply wraps a `[clientId => clientSecret, …]` array.
 * Another is the {@see FileRepository} which reads a `.htpasswd`-style file.
 * More complex implementations may look up the client secret in a database or some other external system.
 */
abstract class KeyRepository implements \ArrayAccess
{

    /**
     * Checks if one client ID is known in this repository.
     *
     * If this returns `true`,
     * the {@see offsetGet} method can be used with the same argument
     * to look up that client's API key.
     *
     * @param string $clientId The client identification to look up.
     * @return bool
     */
    abstract public function offsetExists($clientId): bool;

    /**
     * Returns the client key/secret/hash/password that belongs to one client ID.
     *
     * @param string $clientId The client identification to look up.
     * @return string  The client key. (This might be a symmetric key or hash, a public key, or a plaintext password depending on the {@see AuthenticationMethod} used.)
     * @throws UnknownClientIdException  if the client ID is unknown in this repository.
     */
    abstract public function offsetGet($clientId): string;


    final public function offsetUnset($clientId): void
    {
        throw new ImmutableDataException('KeyRepository cannot be altered');
    }

    final public function offsetSet($clientId, $value): void
    {
        throw new ImmutableDataException('KeyRepository cannot be altered');
    }


    protected static function validateClientId($clientId): void
    {
        if (!is_string($clientId) && !is_int($clientId)) {
            throw new InvalidArgumentException('client_id must be int|string');
        }

        if ($clientId === 0 || $clientId === '' || $clientId === null) {
            throw new InvalidArgumentException('client_id cannot be empty');
        }
    }

    protected static function validateClientKey($clientKey): void
    {
        if (!is_string($clientKey)) {
            throw new InvalidArgumentException('client_key must be string');
        }

        if ($clientKey === '' || $clientKey === null) {
            throw new InvalidArgumentException('client_key cannot be empty');
        }
    }

    protected function requireClientId($clientId): void
    {
        if (!$this->offsetExists($clientId)) {

            $errid = null;
            if (is_int($clientId)) {
                $errid = $clientId;
            } elseif (is_string($clientId)) {
                $errid = '\'' . addcslashes($clientId, "\\'\n") . '\'';
            }

            throw new UnknownClientIdException('unknown client id ' . $errid);
        }
    }

}
