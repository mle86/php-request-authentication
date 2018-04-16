<?php
declare(strict_types=1);
namespace mle86\RequestAuthentication\KeyRepository;

use mle86\RequestAuthentication\Exception\ImmutableDataException;
use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\Exception\UnknownClientIdException;

/**
 * A key repository can look up client API secrets
 * by their client identification.
 *
 * They are needed by {@see AuthenticationMethod::verify()}
 * to look up the correct client API secret
 * for the client identification string
 * contained within the request.
 *
 * A basic implementation is the {@see ArrayRepository} which simply wraps a `[clientId => clientSecret…]` array.
 * More complex implementations may look up the client secret in a database or some other external system.
 */
abstract class KeyRepository
    implements \ArrayAccess
{

    /**
     * Checks if one client ID is known in this repository.
     *
     * If this returns `true`,
     * the {@see offsetGet} method can be used with the same argument
     * to look up that client's API key.
     *
     * @param string $client_id  The client identification to look up.
     * @return bool
     */
    abstract public function offsetExists($client_id): bool;

    /**
     * Returns the client key that belongs to one client ID.
     *
     * @param string $client_id  The client identification to look up.
     * @return string  The client key. (This might be a symmetric or a public key, depending on the {@see AuthenticationMethod} used.)
     * @throws UnknownClientIdException  if the client ID is unknown in this repository.
     */
    abstract public function offsetGet($client_id): string;


    final public function offsetUnset($client_id): void
    {
        throw new ImmutableDataException('KeyRepository cannot be altered');
    }

    final public function offsetSet($client_id, $value): void
    {
        throw new ImmutableDataException('KeyRepository cannot be altered');
    }


    protected static function validateClientId($client_id): void
    {
        if (!is_string($client_id) && !is_int($client_id)) {
            throw new InvalidArgumentException('client_id must be int|string');
        }

        if ($client_id === 0 || $client_id === '' || $client_id === null) {
            throw new InvalidArgumentException('client_id cannot be empty');
        }
    }

    protected static function validateClientKey($client_key): void
    {
        if (!is_string($client_key)) {
            throw new InvalidArgumentException('client_key must be string');
        }

        if ($client_key === '' || $client_key === null) {
            throw new InvalidArgumentException('client_key cannot be empty');
        }
    }

    protected function requireClientId($client_id): void
    {
        if (!$this->offsetExists($client_id)) {

            $errid = null;
            if (is_int($client_id)) {
                $errid = $client_id;
            } elseif (is_string($client_id)) {
                $errid = '\'' . addcslashes($client_id, "\\'\n") . '\'';
            }

            throw new UnknownClientIdException('unknown client id ' . $errid);
        }
    }

}
