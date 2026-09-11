<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\Dsse\Verifier;
use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use K2gl\SdJwtVc\Internal\JwkSet;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use stdClass;
use Throwable;

/**
 * Web-based Issuer key discovery via JWT VC Issuer Metadata
 * (draft-ietf-oauth-sd-jwt-vc Section 4): fetch
 * `/.well-known/jwt-vc-issuer` (inserted between host and path of the `iss`
 * HTTPS URL), require `issuer` to be identical to `iss`, and select the key
 * from `jwks` or `jwks_uri` by the JWT's `kid`.
 *
 * Retrieval follows Section 3: a document counts only if the response is 2xx
 * with `application/json` content, redirects are followed a bounded number
 * of times and only to URLs the {@see UrlPolicy} allows, and the body is
 * read up to a size limit. Time limits belong to the PSR-18 client.
 *
 * ```php
 * $resolver = new JwtVcIssuerMetadata($psr18Client, $psr17RequestFactory);
 * ```
 */
final class JwtVcIssuerMetadata implements IssuerKeyResolver
{
    public const MEDIA_TYPE = 'application/json';

    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly UrlPolicy $urlPolicy = new UrlPolicy,
        private readonly int $maxRedirects = 3,
        private readonly int $maxBytes = 1024 * 1024,
    ) {}

    public function resolve(?string $issuer, stdClass $header): Verifier
    {
        if ($issuer === null) {
            throw new IssuerKeyResolutionFailed('The SD-JWT VC has no "iss" claim to resolve metadata by.');
        }

        $metadata = $this->fetchJson(self::wellKnownUrl($issuer));

        if (($metadata['issuer'] ?? null) !== $issuer) {
            throw new IssuerKeyResolutionFailed(
                'The JWT VC Issuer Metadata "issuer" is not identical to the "iss" claim.',
            );
        }

        $jwks = $metadata['jwks'] ?? null;
        $jwksUri = $metadata['jwks_uri'] ?? null;

        if (is_array($jwks) === is_string($jwksUri)) { // both or neither
            throw new IssuerKeyResolutionFailed(
                'The JWT VC Issuer Metadata must contain either "jwks" or "jwks_uri", but not both.',
            );
        }

        if (is_string($jwksUri)) {
            $jwks = $this->fetchJson($jwksUri);
        }

        $keyId = $header->kid ?? null;

        /** @var array<string, mixed> $jwks */
        return JwkSet::select($jwks, is_string($keyId) ? $keyId : null);
    }

    /**
     * `https://example.com/tenant/1234` ->
     * `https://example.com/.well-known/jwt-vc-issuer/tenant/1234`
     */
    public static function wellKnownUrl(string $issuer): string
    {
        $parts = parse_url($issuer);

        if ($parts === false
            || ($parts['scheme'] ?? '') !== 'https'
            || ! isset($parts['host'])
            || isset($parts['query'])
            || isset($parts['fragment'])) {
            throw new IssuerKeyResolutionFailed(
                'The "iss" claim must be an HTTPS URL without query or fragment to resolve JWT VC Issuer Metadata.',
            );
        }

        $origin = 'https://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        $path = rtrim($parts['path'] ?? '', '/');

        return $origin . '/.well-known/jwt-vc-issuer' . $path;
    }

    /**
     * @return array<string, mixed>
     */
    private function fetchJson(string $url): array
    {
        $response = $this->request($url);
        $contentType = strtolower(trim(explode(';', $response->getHeaderLine('Content-Type'))[0]));

        if ($contentType !== self::MEDIA_TYPE) {
            throw new IssuerKeyResolutionFailed(sprintf(
                'Expected %s from %s, got "%s".',
                self::MEDIA_TYPE,
                $url,
                $response->getHeaderLine('Content-Type'),
            ));
        }

        $decoded = json_decode($this->body($response, $url), true);

        if (! is_array($decoded) || array_is_list($decoded)) {
            throw new IssuerKeyResolutionFailed(sprintf('The document at %s is not a JSON object.', $url));
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
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
                    throw new IssuerKeyResolutionFailed(sprintf('Fetching %s exceeded %d redirects.', $url, $this->maxRedirects));
                }

                $location = $response->getHeaderLine('Location');

                continue;
            }

            throw new IssuerKeyResolutionFailed(sprintf('Fetching %s failed: HTTP %d.', $location, $status));
        }
    }

    private function send(string $url): ResponseInterface
    {
        $request = $this->requestFactory->createRequest('GET', $url)->withHeader('Accept', self::MEDIA_TYPE);

        try {
            return $this->httpClient->sendRequest($request);
        } catch (Throwable $e) {
            throw new IssuerKeyResolutionFailed(sprintf('Fetching %s failed: %s', $url, $e->getMessage()), previous: $e);
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
                throw new IssuerKeyResolutionFailed(sprintf(
                    'The document at %s is larger than %d bytes.',
                    $url,
                    $this->maxBytes,
                ));
            }
        }

        return $body;
    }
}
