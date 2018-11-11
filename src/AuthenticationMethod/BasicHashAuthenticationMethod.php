<?php

namespace mle86\RequestAuthentication\AuthenticationMethod;

use mle86\RequestAuthentication\Crypto\HasherFactory;
use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\InvalidAuthenticationException;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;

/**
 * Implements HTTP “Basic” authentication
 * with hashed password storage.
 *
 * The Basic username is the $apiClientId,
 * the Basic password is the $apiClientKey.
 * A hashed form of the Basic password must also be returned by the KeyRepository.
 *
 * This class expects the KeyRepository to contain only hashed passwords
 * (in contrast to the simpler {@see BasicAuthenticationMethod}
 * which expects the repository to contain plaintext passwords).
 * This works well with `.htpasswd` files and the {@see FileRepository}.
 *
 * The following hash formats are recognized:
 *  - Prefixes `$1$` (MD5),
 *    `$2$`/`$2a$`/`$2x$`/`$2y$` (bcrypt),
 *    `$5$` (SHA-256),
 *    `$6$` (SHA-512),
 *    and `$argon2i$` (Argon2 -- only on PHP7.2+)
 *    as returned by {@see crypt()} and {@see password_hash()}.
 *  - Prefixes
 *    `{SHA}` (SHA-1),
 *    `{SSHA}` (salted SHA-1),
 *    and `$apr1$` (APR1-MD5)
 *    as traditionally used in htpasswd files.
 */
class BasicHashAuthenticationMethod extends BasicAuthenticationMethod
{

    private $hasherFactory;
    public function __construct(HasherFactory $hasherFactory = null)
    {
        $this->hasherFactory = $hasherFactory;
    }

    public function verify(RequestInfo $request, KeyRepository $keys): void
    {
        [$username, $password] = $this->extractAuthenticationData($request);

        $knownPasswordHash = $keys[$username];

        $verifier = $this->getHasherFactory()->getHasher($knownPasswordHash);
        if (!$verifier->test($password, $knownPasswordHash)) {
            throw new InvalidAuthenticationException('auth password mismatch');
        }
    }

    private function getHasherFactory(): HasherFactory
    {
        if (!$this->hasherFactory) {
            $this->hasherFactory = new HasherFactory();
        }
        return $this->hasherFactory;
    }

}
