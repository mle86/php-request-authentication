<?php

namespace mle86\RequestAuthentication\Tests\Helper;

use mle86\RequestAuthentication\AuthenticationMethod\AuthenticationMethod;

/** @internal This trait is used by {@see AuthenticationMethodTests}. */
trait AuthenticationMethodTestConfiguration
{

    /**
     * By default, the output of {@see AuthenticationMethod::authenticate()}
     * should depend on the used client key and on the request data itself.
     *
     * If your test class is testing a method implementation where this is _not_ true,
     * override this method and let it return false.
     *
     * @return bool
     */
    protected function methodOutputDependsOnRequestData(): bool
    {
        return true;
    }

    /**
     * By default, the output of {@see AuthenticationMethod::authenticate()}
     * should include the client identification in some form --
     * it's what the {@see AuthenticationMethod::getClientId} exists for.
     *
     * If your test class is testing an obscure method implementation where this is _not_ true,
     * override this method and let it return false.
     * This will skip the {@see AuthenticationMethodTests::testClientIdGetter()} test entirely.
     *
     * @return bool
     */
    protected function methodOutputIncludesClientId(): bool
    {
        return true;
    }

    /**
     * Override this method if you want to add custom client IDs/keys
     * to the default {@see getTestingKeyRepository}.
     *
     * @return array  [clientId => clientKey…]
     */
    protected function customKeyRepositoryEntries(): array
    {
        return [];
    }

    /**
     * This method should return a list of all authentication-relevant header names
     * used by your authentication method implementation.
     *
     *  - The {@see testMissingHeaderValues} will remove each of them or set them to various empty values,
     *    always expecting {@see AuthenticationMethod::verify()} to throws a {@see MissingAuthenticationHeaderException}.
     *  - The {@see testInvalidHeaderValues} will set each of them to various invalid values,
     *    always expecting {@see AuthenticationMethod::verify()} to throw a {@see InvalidAuthenticationException}.
     *
     * If this is undefined (i.e. returns NULL),
     * all headers usually returned by {@see AuthenticationMethod::authenticate()} are used instead.
     *
     * @return null|array  [headerName, headerName, …]
     */
    protected function authenticationHeaders(): ?array
    {
        return null;
    }

    /**
     * If all requests should carry some headers BEFORE being passed to {@see AuthenticationMethod::authenticate()},
     * override this method to return those headers.
     *
     * @return array [headerName => headerValue, …]
     */
    protected function defaultRequestHeaders(): array
    {
        return [];
    }

    /**
     * Data provider used by {@see AuthenticationMethodTests::testMismatchOnDifferentClient}.
     *
     * See {@see AuthenticationMethodTests::differentClientData()} for the syntax.
     *
     * @return array[][]
     */
    public function customDifferentClientData(): array
    {
        return [];
    }

    /**
     * Data provider used by {@see AuthenticationMethodTests::testInvalidHeaderValues}.
     *
     * See {@see AuthenticationMethodTests::invalidAuthenticationHeaderValues()} for the syntax.
     *
     * @return mixed[][]
     */
    public function customInvalidAuthenticationHeaderValues(): array
    {
        return [];
    }

    /**
     * If you want to add custom tests to your Test class
     * which should run after all the trait test methods have passed,
     * override this function.
     *
     * It will be called by {@see testOther} at the end.
     *
     * @param AuthenticationMethod $method  The instance returned by {@see testGetInstance()}.
     * @param array $original_add_headers  The array returned by {@see testSampleRequest()}.
     */
    protected function otherTests(AuthenticationMethod $method, array $original_add_headers)
    {
    }

}
