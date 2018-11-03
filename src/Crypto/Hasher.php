<?php

namespace mle86\RequestAuthentication\Crypto;

use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;

/**
 * Can be used to compute and verify cryptographic hashes.
 *
 * This is a symmetric operation,
 * so the same class acts both as hasher and hash verifier.
 */
abstract class Hasher
{

    abstract public function hash(string $message): string;

    /**
     * Tests if a hash matches a message.
     *
     * @param string $inputMessage  The input message to test against the known hash.
     * @param string $knownHash     The known hash.
     * @return bool  Returns true if the message matches the known hash, false otherwise.
     */
    public function test(string $inputMessage, string $knownHash): bool
    {
        /*
         * This default implementation
         * assumes that the hash() method returns a plain hash
         * and that re-computing the same message's hash
         * results in the same hash value.
         *
         * This however is not true for some hash methods;
         * for example, PHP's built-in password_hash() includes a random salt
         * which is why they have to be tested with password_verify() instead.
         *
         * Override this method as needed.
         */

        $messageHash = $this->hash($inputMessage);
        return hash_equals($knownHash, $messageHash);
    }

    /**
     * Tests if a hash matches a message
     * and throws an {@see InvalidAuthenticationException} if not.
     *
     * @param string $inputMessage
     * @param string $knownHash
     * @return void  Returns if the hash matches.
     * @throws InvalidAuthenticationException  if the hash does not match.
     */
    final public function verify(string $inputMessage, string $knownHash): void
    {
        if (!$this->test($inputMessage, $knownHash)) {
            throw new InvalidAuthenticationException('hash mismatch');
        }
    }

}
