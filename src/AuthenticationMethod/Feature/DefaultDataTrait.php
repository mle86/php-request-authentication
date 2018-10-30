<?php

namespace mle86\RequestAuthentication\AuthenticationMethod\Feature;

use mle86\RequestAuthentication\DTO\RequestInfo;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;

/**
 * This trait provides the {@see signableRequestData()} method
 * which extracts some standard request data
 * for the token/signature calculation.
 */
trait DefaultDataTrait
{

    /**
     * In order to create an authenticated signature for the request,
     * some request data must be included in the raw signable data.
     *
     * Not all of it (many HTTP headers are not security-relevant),
     * but the HTTP method, the exact URI (including host and query string), and the request body
     * must be included to be reasonably safe against request forgery.
     *
     * Callers may specify any number of additional header values
     * that will become part of the signature.
     * (Additionally, this method always includes the Content-Type header.)
     *
     * @param RequestInfo $request   The request to sign.
     * @param array $useHeaders      Header names whose values should be included in the output.
     * @param array $overrideHeaders Overridden header values that take precedence over $request's header values.
     * @return string  Signable request-dependent raw output.
     *                 This should NOT be sent anywhere, it should be used for HMAC hashing or some other cryptographic signing process.
     */
    protected static function signableRequestData(
        RequestInfo $request,
        array $useHeaders = [],
        array $overrideHeaders = []
    ): string {
        $overrideHeaders = array_change_key_case($overrideHeaders, \CASE_LOWER);

        $hdr = function(string $headerName) use($request, $overrideHeaders): string {
            try {
                $headerName = strtolower($headerName);
                return
                    $overrideHeaders[$headerName] ??
                    $request->getHeaderValue($headerName) ??
                    '';
            } catch (MissingAuthenticationHeaderException $e) {
                return '';
            }
        };

        // Separator character.
        // Linebreak is used because it cannot be contained in HTTP header values nor in the request URI.
        // Also hash functions don't have any problems with it (unlike with NUL).
        $separator = "\n";

        // always include these header values:
        $headerInfo = '';
        $forceUseHeaders = ['Content-Type'];
        foreach ($forceUseHeaders as $useHeaderName) {
            $headerInfo .= $hdr($useHeaderName) . $separator;
        }
        // attach more header values as requested:
        foreach ($useHeaders as $useHeaderName) {
            $headerInfo .= $hdr($useHeaderName) . $separator;
        }

        return
            // HTTP method and exact URI:
            "{$request->getHttpMethod()} {$request->getUri()}" . $separator .
            // Header values based on $forceUseHeaders and $useHeaders:
            $headerInfo .
            // Full request body, if present:
            $request->getRequestBody();
    }

}
