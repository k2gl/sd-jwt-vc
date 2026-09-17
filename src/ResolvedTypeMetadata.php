<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\SdJwtVc\Exception\TypeMetadataException;

/**
 * The Type Metadata of a credential type with its `extends` chain resolved
 * (draft-ietf-oauth-sd-jwt-vc Sections 5.4–5.6): the documents from the type
 * itself up to the root of the chain, and what they add up to — the claim
 * metadata after extension (child properties win, `sd` and `mandatory` cannot
 * be loosened) and the display metadata of the nearest type that defines any.
 */
final class ResolvedTypeMetadata
{
    /** Extension chains deeper than this are refused; real ones are a few types long. */
    public const MAX_DEPTH = 8;

    /** @var list<ClaimMetadata> */
    private readonly array $claims;

    /**
     * @param list<TypeMetadata> $chain the type itself first, then what it extends, and so on
     */
    private function __construct(private readonly array $chain)
    {
        $this->claims = self::effectiveClaims($chain);
    }

    /**
     * Retrieve and process the type's metadata and every type it extends,
     * extended types first (Section 5.4), detecting circular chains (Section 7.4).
     */
    public static function resolve(TypeMetadataResolver $resolver, string $vct, ?string $integrity): self
    {
        $chain = [];
        $seen = [];

        while (true) {
            if (isset($seen[$vct])) {
                throw new TypeMetadataException(sprintf('The Type Metadata for "%s" extends itself, directly or through other types.', $vct));
            }

            if (count($chain) >= self::MAX_DEPTH) {
                throw new TypeMetadataException(sprintf('The Type Metadata "extends" chain is deeper than %d types.', self::MAX_DEPTH));
            }
            $seen[$vct] = true;
            $metadata = $resolver->resolve($vct, $integrity);
            $chain[] = $metadata;

            if ($metadata->extends === null) {
                return new self($chain);
            }
            $vct = $metadata->extends;
            $integrity = $metadata->extendsIntegrity;
        }
    }

    /** The credential type the chain was resolved for. */
    public function vct(): string
    {
        return $this->chain[0]->vct;
    }

    /** The type's own document. */
    public function type(): TypeMetadata
    {
        return $this->chain[0];
    }

    /**
     * The documents from the type itself up to the root of the `extends` chain.
     *
     * @return list<TypeMetadata>
     */
    public function chain(): array
    {
        return $this->chain;
    }

    /**
     * The claim metadata after applying the extensions (Section 5.6.5).
     *
     * @return list<ClaimMetadata>
     */
    public function claims(): array
    {
        return $this->claims;
    }

    /**
     * The display metadata of the type, or of the nearest extended type when the
     * type defines none (Section 5.5.2).
     *
     * @return ?list<array<string, mixed>>
     */
    public function display(): ?array
    {
        foreach ($this->chain as $metadata) {
            if ($metadata->display !== null) {
                return $metadata->display;
            }
        }

        return null;
    }

    /**
     * @param list<TypeMetadata> $chain
     * @return list<ClaimMetadata>
     */
    private static function effectiveClaims(array $chain): array
    {
        /** @var array<string, ClaimMetadata> $byPath */
        $byPath = [];

        foreach (array_reverse($chain) as $metadata) {
            foreach ($metadata->claims ?? [] as $claim) {
                $key = $claim->pathKey();
                $byPath[$key] = isset($byPath[$key]) ? $byPath[$key]->overriddenBy($claim) : $claim;
            }
        }

        return array_values($byPath);
    }
}
