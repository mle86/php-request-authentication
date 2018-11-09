<?php

declare(strict_types=1);

namespace mle86\RequestAuthentication\KeyRepository;

use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\Exception\RepositorySourceException;

/**
 * A client key repository based on a `htpasswd`-style file.
 *
 * The constructor takes a filename
 * and ensures it's not a directory's name.
 *
 * The constructor does however not check the filename for existence, readability, or format.
 * This is done once on the first actual usage of the repository ({@see offsetExists}/{@see offsetGet}).
 * If you want to force these checks and the file read early, call the {@see forceRead()} method.
 *
 * The file will _not_ be re-read on multiple {@see offsetGet} calls.
 *
 * The expected file format is that of htpasswd files:
 *  - One `clientId:clientKey` pair per line.
 *  - clientId must be non-empty and cannot contain colons.
 *  - clientKey must be non-empty.
 *  - Leading and trailing whitespace will be removed.
 *  - Empty lines, whitespace-only lines and lines starting with a "`#`" will be ignored.
 *
 * Real htpasswd files usually contain password hashes instead of plaintext passwords,
 * making them useless for our {@see BasicAuthenticationMethod}
 * (which works with plaintext client keys only).
 * Use the {@see BasicHashAuthenticationMethod} instead,
 * it understands most hash methods traditionally used in htpasswd files.
 * You may of course also store public keys in a htpasswd-style key repository files
 * to use with a class like {@see PublicKeyMethod}.
 */
class FileRepository extends KeyRepository
{

    private $filename;
    public function __construct(string $filename)
    {
        $this->filename = $filename;

        if (file_exists($filename) && !is_file($filename)) {
            throw new RepositorySourceException("not a file: '{$filename}'");
        }
    }

    /**
     * Forces the source file to be read immediately.
     *
     * (This only has an effect once and only prior to the first {@see offsetExists}/{@see offsetGet} call.)
     */
    public function forceRead(): self
    {
        $this->getArrayRepository();
        return $this;
    }

    private static function readFile(string $filename): array
    {
        if (!file_exists($filename)) {
            throw new RepositorySourceException("key repository file does not exist: '{$filename}'");
        }
        if (!is_file($filename)) {
            throw new RepositorySourceException("key repository is not a file: '{$filename}'");
        }
        if (!is_readable($filename)) {
            throw new RepositorySourceException("key repository file not readable: '{$filename}'");
        }

        $output = [];
        $lineno = 0;
        foreach (file($filename, \FILE_IGNORE_NEW_LINES) as $line) {
            $lineno++;

            $trimmed = trim($line);
            if ($trimmed === '' || $trimmed[0] === '#') {
                // this is a comment line or a whitespace-only line, ignore.
                continue;
            }

            $parts = explode(':', $trimmed, 2);
            if (count($parts) !== 2) {
                throw new RepositorySourceException("key repository malformed on line {$lineno}: '{$filename}'");
            }

            // The ArrayRepository constructor also validated its input
            // but it'd use another exception class and cannot include the line number.
            try {
                self::validateClientKey($parts[0]);
                self::validateClientKey($parts[1]);
            } catch (InvalidArgumentException $e) {
                throw new RepositorySourceException("key repository malformed on line {$lineno}: '{$filename}'", 0, $e);
            }

            $output[ $parts[0] ] = $parts[1];
        }

        return $output;
    }

    private $arrayRepository;
    private function getArrayRepository(): ArrayRepository
    {
        if (!$this->arrayRepository) {
            $this->arrayRepository = new ArrayRepository(
                self::readFile($this->filename));
        }
        return $this->arrayRepository;
    }

    public function offsetExists($clientId): bool
    {
        return $this->getArrayRepository()->offsetExists($clientId);
    }

    public function offsetGet($clientId): string
    {
        return $this->getArrayRepository()->offsetGet($clientId);
    }

}
