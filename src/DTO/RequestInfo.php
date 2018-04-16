<?php
namespace mle86\RequestAuthentication\DTO;

use mle86\RequestAuthentication\Exception\InvalidArgumentException;
use mle86\RequestAuthentication\Exception\MissingAuthenticationHeaderException;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Encapsulates all relevant information about one HTTP request.
 */
class RequestInfo
{

    private $http_method;   // GET
    private $http_proto;    // https
    private $http_host;     // www.domain.test:8080
    private $http_path;     // /foo/bar?123
    private $request_body;  // input1=value1&input2=value2
    private $request_headers;  // [Content-Type => application/x-www-form-urlencoded, Conent-Length => 27]

    const REPEATED_HEADERS_JOIN = "\x00";

    /**
     * RequestInfo constructor.
     *
     * @param string $http_method  HTTP method verb, in uppercase letters (e.g. "GET").
     * @param string $http_proto  HTTP procotol (e.g. "https").
     * @param string $http_host  HTTP host, including port if non-default (e.g. "www.domain.test" or "www2.domain.test:8080").
     * @param string $http_path  Full HTTP path including query string (e.g.  "/info.html" or "/").
     * @param string $request_body  Raw request body contents.
     * @param array $request_headers  All HTTP headers included in the request: [headerName => headerValue…].
     *                                In case of array headerValues, they will be joined with \x00 (NUL) characters.
     */
    public function __construct(
        string $http_method,
        string $http_proto,
        string $http_host,
        string $http_path = '/',
        string $request_body = '',
        array $request_headers = []
    )
    {
        $this->http_method     = $http_method;
        $this->http_proto      = $http_proto;
        $this->http_host       = $http_host;
        $this->http_path       = $http_path;
        $this->request_body    = $request_body;
        $this->request_headers = array_change_key_case($request_headers, \CASE_LOWER);

        foreach ($this->request_headers as $key => &$value) {
            if (is_array($value)) {
                foreach ($value as $v) {
                    if (!is_scalar($v)) {
                        throw new InvalidArgumentException('headers values must be scalar or scalar[]');
                    }
                }
                $value = implode(self::REPEATED_HEADERS_JOIN, $value);
            } elseif (!is_scalar($value)) {
                throw new InvalidArgumentException('headers values must be scalar or scalar[]');
            }
        }
        unset($value);
    }

    public static function fromGlobals(): self
    {
        $proto = strtolower($_SERVER['REQUEST_SCHEME']);

        $host = $_SERVER['SERVER_NAME'];
        $port = (int)$_SERVER['SERVER_PORT'];
        if (($proto === 'http' && $port !== 80) || ($proto === 'https' && $port !== 443)) {
            $host .= ':' . $port;
        }

        $in = fopen('php://input', 'rb');
        rewind($in);
        $request_body = stream_get_contents($in);
        rewind($in);
        fclose($in);

        $headers = [];
        foreach ($_SERVER as $key => $value) {
            if (substr($key, 0, 5) !== 'HTTP_') {
                continue;
            }

            $header_name = str_replace(
                '_',
                '-',
                substr($key, 5));  // remove HTTP_ prefix

            $headers[$header_name] = $value;
        }

        return new self(
            strtoupper($_SERVER['REQUEST_METHOD']),
            $proto,
            $host,
            $_SERVER['REQUEST_URI'],
            $request_body,
            $headers
        );
    }

    public static function fromSymfonyRequest(Request $request): self
    {
        return new self(
            $request->getRealMethod(),
            $request->getScheme(),
            $request->getHttpHost(),
            $request->getRequestUri(),
            $request->getContent(),
            $request->headers->all()
        );
    }

    /**
     * Builds a {@see RequestInfo} instance from a PSR-7 {@see RequestInterface}.
     *
     * SIDE EFFECT: This will cause a {@see StreamInterface::rewind()} call
     *  on {@see RequestInterface::getBody()}.
     *
     * @param RequestInterface $request
     * @return RequestInfo
     */
    public static function fromPsr7(RequestInterface $request): self
    {
        $uri = $request->getUri();

        $path = $uri->getPath();
        $query = $uri->getQuery();
        if ($query !== null && $query !== '') {
            $path .= '?' . $query;
        }

        $request->getBody()->rewind();
        $body = $request->getBody()->getContents();
        $request->getBody()->rewind();

        return new self(
            $request->getMethod(),
            $uri->getScheme(),
            $uri->getAuthority(),
            $path,
            $body,
            $request->getHeaders()
        );
    }


    public function getHttpMethod(): string
    {
        return $this->http_method;
    }

    public function getHttpProtocol(): string
    {
        return $this->http_proto;
    }

    public function getHttpHost(): string
    {
        return $this->http_host;
    }

    public function getHttpPath(): string
    {
        return $this->http_path;
    }

    public function getUri(): string
    {
        return $this->http_proto . '://' . $this->http_host . $this->http_path;
    }

    public function getRequestBody(): string
    {
        return $this->request_body;
    }

    public function getRequestHeaders(): array
    {
        return $this->request_headers;
    }

    public function hasHeader(string $header_name): bool
    {
        $lower_header_name = strtolower($header_name);
        return array_key_exists($lower_header_name, $this->request_headers);
    }

    public function getHeaderValue(string $header_name): ?string
    {
        if ($header_name === '') {
            throw new InvalidArgumentException('header_name cannot be empty');
        }

        $lower_header_name = strtolower($header_name);
        if (!array_key_exists($lower_header_name, $this->request_headers)) {
            throw new MissingAuthenticationHeaderException('no \'' . $header_name . '\' header');
        }

        if ($this->request_headers[$lower_header_name] === '') {
            return null;
        }

        return $this->request_headers[$lower_header_name];
    }

    public function getNonemptyHeaderValue(string $header_name): string
    {
        $header = $this->getHeaderValue($header_name);
        if ($header === null || $header === '') {
            throw new MissingAuthenticationHeaderException('empty \'' . $header_name . '\' header');
        }

        return $header;
    }

}
