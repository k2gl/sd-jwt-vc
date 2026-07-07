<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\Dsse\Verifier;
use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use K2gl\SdJwtVc\Internal\JwkSet;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use stdClass;
use Throwable;

/**
 * Web-based Issuer key discovery via JWT VC Issuer Metadata
 * (draft-ietf-oauth-sd-jwt-vc Section 3): fetch
 * `/.well-known/jwt-vc-issuer` (inserted between host and path of the `iss`
 * HTTPS URL), require `issuer` to be identical to `iss`, and select the key
 * from `jwks` or `jwks_uri` by the JWT's `kid`.
 *
 * ```php
 * $resolver = new JwtVcIssuerMetadata($psr18Client, $psr17RequestFactory);
 * ```
 */
final class JwtVcIssuerMetadata implements IssuerKeyResolver
{
    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
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
        try {
            $response = $this->httpClient->sendRequest($this->requestFactory->createRequest('GET', $url));
        } catch (Throwable $e) {
            throw new IssuerKeyResolutionFailed(sprintf('Fetching %s failed: %s', $url, $e->getMessage()), previous: $e);
        }

        if ($response->getStatusCode() !== 200) {
            throw new IssuerKeyResolutionFailed(sprintf('Fetching %s failed: HTTP %d.', $url, $response->getStatusCode()));
        }

        $decoded = json_decode((string) $response->getBody(), true);

        if (! is_array($decoded)) {
            throw new IssuerKeyResolutionFailed(sprintf('The document at %s is not a JSON object.', $url));
        }

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }
}
