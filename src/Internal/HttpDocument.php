<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Internal;

use Closure;
use K2gl\SdJwtVc\Exception\SdJwtVcException;
use K2gl\SdJwtVc\UrlPolicy;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Throwable;

/**
 * A JSON document fetched under the retrieval rules of draft-ietf-oauth-sd-jwt-vc
 * Section 3: it counts only if the response is 2xx with `application/json`,
 * redirects are followed a bounded number of times and only to URLs the
 * {@see UrlPolicy} allows, and the body is read up to a size limit. Time limits
 * belong to the PSR-18 client. Failures are raised through the exception the
 * caller supplies, so key discovery and Type Metadata each keep their own.
 *
 * @internal
 */
final class HttpDocument
{
    public const MEDIA_TYPE = 'application/json';

    /**
     * @param Closure(string, ?Throwable): SdJwtVcException $failure
     */
    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly UrlPolicy $urlPolicy,
        private readonly int $maxRedirects,
        private readonly int $maxBytes,
        private readonly Closure $failure,
    ) {}

    /**
     * The document's octets and its decoded JSON object.
     *
     * @return array{0: string, 1: array<string, mixed>}
     */
    public function fetchJsonObject(string $url): array
    {
        $response = $this->request($url);
        $contentType = strtolower(trim(explode(';', $response->getHeaderLine('Content-Type'))[0]));

        if ($contentType !== self::MEDIA_TYPE) {
            throw ($this->failure)(sprintf(
                'Expected %s from %s, got "%s".',
                self::MEDIA_TYPE,
                $url,
                $response->getHeaderLine('Content-Type'),
            ), null);
        }
        $octets = $this->body($response, $url);
        $decoded = json_decode($octets, true);

        if (! is_array($decoded) || array_is_list($decoded)) {
            throw ($this->failure)(sprintf('The document at %s is not a JSON object.', $url), null);
        }

        /** @var array<string, mixed> $decoded */
        return [$octets, $decoded];
    }

    /** GET with redirects followed by hand, so that every hop passes the URL policy. */
    private function request(string $url): ResponseInterface
    {
        $location = $url;

        for ($hop = 0; ; $hop++) {
            $this->urlPolicy->assertAllowed($location);
            $response = $this->send($location);
            $status = $response->getStatusCode();

            if ($status >= 200 && $status < 300) {
                return $response;
            }

            if ($status >= 300 && $status < 400 && $response->hasHeader('Location')) {
                if ($hop >= $this->maxRedirects) {
                    throw ($this->failure)(sprintf('Fetching %s exceeded %d redirects.', $url, $this->maxRedirects), null);
                }

                $location = $response->getHeaderLine('Location');

                continue;
            }

            throw ($this->failure)(sprintf('Fetching %s failed: HTTP %d.', $location, $status), null);
        }
    }

    private function send(string $url): ResponseInterface
    {
        $request = $this->requestFactory->createRequest('GET', $url)->withHeader('Accept', self::MEDIA_TYPE);

        try {
            return $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw ($this->failure)(sprintf('Fetching %s failed: %s', $url, $e->getMessage()), $e);
        }
    }

    /** The response body, read in chunks and abandoned once it exceeds the size limit. */
    private function body(ResponseInterface $response, string $url): string
    {
        $stream = $response->getBody();
        $body = '';

        while (! $stream->eof()) {
            $chunk = $stream->read(8192);

            if ($chunk === '') {
                break;
            }

            $body .= $chunk;

            if (strlen($body) > $this->maxBytes) {
                throw ($this->failure)(sprintf('The document at %s is larger than %d bytes.', $url, $this->maxBytes), null);
            }
        }

        return $body;
    }
}
