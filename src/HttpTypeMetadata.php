<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\SdJwtVc\Exception\TypeMetadataException;
use K2gl\SdJwtVc\Internal\HttpDocument;
use K2gl\SdJwtVc\Internal\Integrity;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Throwable;

/**
 * Type Metadata from the URL in the `vct` claim (draft-ietf-oauth-sd-jwt-vc
 * Section 5.3.1): a `GET` of the HTTPS URL under the Section 3 retrieval
 * rules — 2xx and `application/json` only, redirects followed by hand through
 * the {@see UrlPolicy}, the body capped — with the integrity check of Section 6
 * when the credential or the extending type gives one.
 *
 * ```php
 * $verifier = new SdJwtVcVerifier(typeMetadata: new HttpTypeMetadata($psr18Client, $psr17RequestFactory));
 * ```
 */
final class HttpTypeMetadata implements TypeMetadataResolver
{
    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly UrlPolicy $urlPolicy = new UrlPolicy,
        private readonly int $maxRedirects = 3,
        private readonly int $maxBytes = 1024 * 1024,
    ) {}

    public function resolve(string $vct, ?string $integrity): TypeMetadata
    {
        $parts = parse_url($vct);

        if ($parts === false || ($parts['scheme'] ?? '') !== 'https' || ! isset($parts['host']) || isset($parts['fragment'])) {
            throw new TypeMetadataException(sprintf('Type Metadata for "%s" cannot be retrieved: not an HTTPS URL.', $vct));
        }
        $document = new HttpDocument(
            $this->httpClient,
            $this->requestFactory,
            $this->urlPolicy,
            $this->maxRedirects,
            $this->maxBytes,
            static fn (string $message, ?Throwable $previous): TypeMetadataException => new TypeMetadataException($message, previous: $previous),
        );
        [$octets, $decoded] = $document->fetchJsonObject($vct);

        if ($integrity !== null) {
            Integrity::verify($octets, $integrity, 'Type Metadata for ' . $vct);
        }
        $metadata = TypeMetadata::fromArray($decoded);

        if ($metadata->vct !== $vct) {
            throw new TypeMetadataException(sprintf('The Type Metadata at %s describes "%s", not that type.', $vct, $metadata->vct));
        }

        return $metadata;
    }
}
