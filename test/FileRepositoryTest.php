<?php

namespace mle86\RequestAuthentication\Tests;

use mle86\RequestAuthentication\Exception\RepositorySourceException;
use mle86\RequestAuthentication\KeyRepository\FileRepository;
use mle86\RequestAuthentication\KeyRepository\KeyRepository;
use mle86\RequestAuthentication\Tests\Helper\AssertException;
use mle86\RequestAuthentication\Tests\Helper\KeyRepositoryTests;
use PHPUnit\Framework\TestCase;

class FileRepositoryTest extends TestCase
{
    use AssertException;
    use KeyRepositoryTests;


    public static function defaultData(): array { return [
        'a1' => 'V1',
        'b2' => 'V11',
        'c3' => 'V111',
        'd4' => 'V1111',
    ]; }

    public static function validFiles(): array { return [
        [__DIR__ . '/Helper/htpasswd/valid.htpasswd'],
    ]; }

    public static function invalidFiles(): array { return [
        // Those all exist but are malformed:
        [__DIR__ . '/Helper/htpasswd/invalid1.htpasswd'],
        [__DIR__ . '/Helper/htpasswd/invalid2.htpasswd'],
        [__DIR__ . '/Helper/htpasswd/invalid3.htpasswd'],
        [__DIR__ . '/Helper/htpasswd/invalid4.htpasswd'],
    ]; }

    public static function invalidFilenames(): array { return [
        // Those either don't exist at all, are unreadable, or they are not files:
        [__DIR__ . '/Helper/htpasswd/non-existing-293483465.htpasswd'],
        ['/dev'],
        ['/proc/kmsg'],
        ['/missing-directory-9865450010001/'],
        ['/missing-directory-9865450010001/file'],
        [''],
    ]; }


    public function testGetInstance(): KeyRepository
    {
        return new FileRepository(self::validFiles()[0][0]);
    }

    /**
     * @dataProvider invalidFiles
     */
    public function testInvalidFile(string $filename): void
    {
        $this->assertException(RepositorySourceException::class, function() use($filename) {
            (new FileRepository($filename))->forceRead();
        });
    }

    /**
     * @dataProvider invalidFilenames
     */
    public function testInvalidFilename(string $filename): void
    {
        $this->assertException(RepositorySourceException::class, function() use($filename) {
            (new FileRepository($filename))->forceRead();
        });
    }

}
