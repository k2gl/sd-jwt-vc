<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use JsonException;
use K2gl\SdJwtVc\Exception\TypeMetadataException;

/**
 * A Type Metadata document (draft-ietf-oauth-sd-jwt-vc Section 5.2): what a
 * credential type is called, what it extends, how to display it and what its
 * claims are. One document; the `extends` chain and the effective metadata
 * are {@see ResolvedTypeMetadata}'s business.
 *
 * Properties this package does not understand are kept in {@see raw()} and
 * otherwise ignored, as the draft asks.
 */
final class TypeMetadata
{
    /**
     * @param ?list<array<string, mixed>> $display
     * @param ?list<ClaimMetadata> $claims
     * @param array<string, mixed> $raw
     */
    private function __construct(
        public readonly string $vct,
        public readonly ?string $name,
        public readonly ?string $description,
        public readonly ?string $extends,
        public readonly ?string $extendsIntegrity,
        public readonly ?array $display,
        public readonly ?array $claims,
        private readonly array $raw,
    ) {}

    public static function fromJson(string $json): self
    {
        try {
            $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new TypeMetadataException('Type Metadata is not valid JSON: ' . $e->getMessage(), previous: $e);
        }

        if (! is_array($decoded) || array_is_list($decoded)) {
            throw new TypeMetadataException('Type Metadata must be a JSON object.');
        }

        /** @var array<string, mixed> $decoded */
        return self::fromArray($decoded);
    }

    /**
     * @param array<string, mixed> $document
     */
    public static function fromArray(array $document): self
    {
        $vct = $document['vct'] ?? null;

        if (! is_string($vct) || $vct === '') {
            throw new TypeMetadataException('Type Metadata must name its type in "vct".');
        }
        $extends = self::optionalString($document, 'extends');
        $extendsIntegrity = self::optionalString($document, 'extends#integrity');

        if ($extends === null && $extendsIntegrity !== null) {
            throw new TypeMetadataException('Type Metadata carries "extends#integrity" without "extends".');
        }
        $display = $document['display'] ?? null;

        if ($display !== null) {
            if (! is_array($display) || ! array_is_list($display)) {
                throw new TypeMetadataException('Type Metadata "display" must be an array.');
            }

            foreach ($display as $entry) {
                if (! is_array($entry) || ! is_string($entry['locale'] ?? null) || ! is_string($entry['name'] ?? null)) {
                    throw new TypeMetadataException('A Type Metadata "display" entry needs a "locale" and a "name".');
                }
            }
        }
        $claims = $document['claims'] ?? null;

        if ($claims !== null) {
            if (! is_array($claims) || ! array_is_list($claims)) {
                throw new TypeMetadataException('Type Metadata "claims" must be an array.');
            }
            $svgIds = [];
            $parsed = [];

            foreach ($claims as $object) {
                if (! is_array($object)) {
                    throw new TypeMetadataException('Each Type Metadata "claims" entry must be an object.');
                }

                /** @var array<string, mixed> $object */
                $claim = ClaimMetadata::fromArray($object);

                if ($claim->svgId !== null) {
                    if (isset($svgIds[$claim->svgId])) {
                        throw new TypeMetadataException(sprintf('The claim "svg_id" "%s" is used more than once.', $claim->svgId));
                    }
                    $svgIds[$claim->svgId] = true;
                }
                $parsed[] = $claim;
            }
            $claims = $parsed;
        }

        /** @var ?list<array<string, mixed>> $display */
        return new self(
            vct: $vct,
            name: self::optionalString($document, 'name'),
            description: self::optionalString($document, 'description'),
            extends: $extends,
            extendsIntegrity: $extendsIntegrity,
            display: $display,
            claims: $claims,
            raw: $document,
        );
    }

    /**
     * The document as decoded, every property included.
     *
     * @return array<string, mixed>
     */
    public function raw(): array
    {
        return $this->raw;
    }

    /** @param array<string, mixed> $document */
    private static function optionalString(array $document, string $key): ?string
    {
        $value = $document[$key] ?? null;

        if ($value === null) {
            return null;
        }

        if (! is_string($value) || $value === '') {
            throw new TypeMetadataException(sprintf('Type Metadata "%s" must be a non-empty string.', $key));
        }

        return $value;
    }
}
