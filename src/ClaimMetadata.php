<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\SdJwtVc\Exception\TypeMetadataException;

/**
 * Metadata for one claim, or a set of claims, of a credential type
 * (draft-ietf-oauth-sd-jwt-vc Section 5.6): which claims it addresses (`path`),
 * whether they must be selectively disclosable (`sd`), whether the Issuer must
 * include them (`mandatory`), how to show them (`display`), and their SVG
 * placeholder (`svg_id`).
 */
final class ClaimMetadata
{
    public const SD_ALWAYS = 'always';

    public const SD_ALLOWED = 'allowed';

    public const SD_NEVER = 'never';

    /**
     * @param list<string|int|null> $path
     * @param ?list<array<string, mixed>> $display
     */
    private function __construct(
        public readonly array $path,
        private readonly ?string $sd,
        private readonly ?bool $mandatory,
        public readonly ?array $display,
        public readonly ?string $svgId,
    ) {}

    /**
     * @param array<string, mixed> $object
     */
    public static function fromArray(array $object): self
    {
        $path = $object['path'] ?? null;

        if (! is_array($path) || $path === [] || ! array_is_list($path)) {
            throw new TypeMetadataException('A claim metadata "path" must be a non-empty array.');
        }
        $components = [];

        foreach ($path as $component) {
            if (! is_string($component) && $component !== null && ! (is_int($component) && $component >= 0)) {
                throw new TypeMetadataException('A claim "path" holds strings, null values and non-negative integers only.');
            }
            $components[] = $component;
        }
        $sd = $object['sd'] ?? null;

        if ($sd !== null && ! in_array($sd, [self::SD_ALWAYS, self::SD_ALLOWED, self::SD_NEVER], true)) {
            throw new TypeMetadataException('A claim "sd" must be "always", "allowed" or "never".');
        }
        $mandatory = $object['mandatory'] ?? null;

        if ($mandatory !== null && ! is_bool($mandatory)) {
            throw new TypeMetadataException('A claim "mandatory" must be a boolean.');
        }
        $display = $object['display'] ?? null;
        $entries = null;

        if ($display !== null) {
            if (! is_array($display) || ! array_is_list($display)) {
                throw new TypeMetadataException('A claim "display" must be an array.');
            }
            $entries = [];

            foreach ($display as $entry) {
                if (! is_array($entry) || ! is_string($entry['locale'] ?? null) || ! is_string($entry['label'] ?? null)) {
                    throw new TypeMetadataException('A claim "display" entry needs a "locale" and a "label".');
                }

                /** @var array<string, mixed> $entry */
                $entries[] = $entry;
            }
        }
        $svgId = $object['svg_id'] ?? null;

        if ($svgId !== null && (! is_string($svgId) || preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $svgId) !== 1)) {
            throw new TypeMetadataException('A claim "svg_id" must be alphanumeric with underscores and not start with a digit.');
        }

        return new self($components, $sd, $mandatory, $entries, $svgId);
    }

    /** `always`, `allowed` or `never`. */
    public function sd(): string
    {
        return $this->sd ?? self::SD_ALLOWED;
    }

    public function mandatory(): bool
    {
        return $this->mandatory ?? false;
    }

    /** The path as JSON, for telling two claim metadata objects for the same claims apart. */
    public function pathKey(): string
    {
        return json_encode($this->path, JSON_THROW_ON_ERROR);
    }

    /**
     * This metadata as an extending type overrides it (Section 5.6.5): the
     * child's properties win, one by one, except that `sd` fixed to always or
     * never and `mandatory` set to true cannot be changed back (Section 5.6.5.1).
     */
    public function overriddenBy(self $child): self
    {
        if ($child->sd !== null && $this->sd !== null && $this->sd !== self::SD_ALLOWED && $child->sd !== $this->sd) {
            throw new TypeMetadataException(sprintf(
                'The type extending %s changes "sd" from "%s" to "%s", which an extension must not do.',
                $this->pathKey(),
                $this->sd,
                $child->sd,
            ));
        }

        if ($child->mandatory === false && $this->mandatory === true) {
            throw new TypeMetadataException(sprintf(
                'The type extending %s makes a mandatory claim optional, which an extension must not do.',
                $this->pathKey(),
            ));
        }

        return new self(
            $this->path,
            $child->sd ?? $this->sd,
            $child->mandatory ?? $this->mandatory,
            $child->display ?? $this->display,
            $child->svgId ?? $this->svgId,
        );
    }
}
