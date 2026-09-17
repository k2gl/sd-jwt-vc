<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\SdJwtVc\Exception\TypeMetadataException;
use K2gl\SdJwtVc\Internal\Integrity;

/**
 * Type Metadata from documents held locally — a registry (Section 5.3.2), a
 * cache populated ahead of time (Section 5.3.4), or types that are not HTTPS
 * URLs at all. Documents are kept as the octets they were published as, so
 * that integrity metadata still applies to them.
 *
 * ```php
 * $registry = (new StaticTypeMetadata)
 *     ->add('https://credentials.example.com/identity_credential', $json);
 * ```
 */
final class StaticTypeMetadata implements TypeMetadataResolver
{
    /** @var array<string, string> */
    private array $documents = [];

    /** Register the document for a type, as its JSON octets. */
    public function add(string $vct, string $json): self
    {
        $this->documents[$vct] = $json;

        return $this;
    }

    public function resolve(string $vct, ?string $integrity): TypeMetadata
    {
        $octets = $this->documents[$vct] ?? null;

        if ($octets === null) {
            throw new TypeMetadataException(sprintf('No Type Metadata is registered for "%s".', $vct));
        }

        if ($integrity !== null) {
            Integrity::verify($octets, $integrity, 'Type Metadata for ' . $vct);
        }
        $metadata = TypeMetadata::fromJson($octets);

        if ($metadata->vct !== $vct) {
            throw new TypeMetadataException(sprintf('The Type Metadata registered for "%s" describes "%s".', $vct, $metadata->vct));
        }

        return $metadata;
    }
}
