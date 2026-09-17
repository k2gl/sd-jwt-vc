<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\Dsse\Verifier;
use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use K2gl\SdJwtVc\Internal\HttpDocument;
use K2gl\SdJwtVc\Internal\JwkSet;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
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
    public const MEDIA_TYPE = HttpDocument::MEDIA_TYPE;

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
        return $this->document()->fetchJsonObject($url)[1];
    }

    private function document(): HttpDocument
    {
        return new HttpDocument(
            $this->httpClient,
            $this->requestFactory,
            $this->urlPolicy,
            $this->maxRedirects,
            $this->maxBytes,
            static fn (string $message, ?Throwable $previous): IssuerKeyResolutionFailed => new IssuerKeyResolutionFailed($message, previous: $previous),
        );
    }
}
