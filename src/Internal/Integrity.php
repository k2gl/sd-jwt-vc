<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Internal;

use K2gl\SdJwtVc\Exception\TypeMetadataException;

/**
 * Integrity of a referenced document (draft-ietf-oauth-sd-jwt-vc Section 6):
 * the `#integrity` value is W3C SRI integrity metadata — one or more
 * `<alg>-<base64 digest>` expressions separated by whitespace — and the
 * retrieved octets must hash to one of the digests given for the strongest
 * hash algorithm the consumer supports.
 *
 * @internal
 */
final class Integrity
{
    /** Strongest first. */
    private const ALGORITHMS = ['sha512', 'sha384', 'sha256'];

    public static function verify(string $octets, string $integrity, string $what): void
    {
        $digestsByAlgorithm = [];

        foreach (preg_split('/\s+/', trim($integrity)) ?: [] as $expression) {
            if ($expression === '') {
                continue;
            }
            // SRI allows "?options" after the digest; none are defined.
            [$expression] = explode('?', $expression, 2);
            $parts = explode('-', $expression, 2);

            if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
                throw new TypeMetadataException(sprintf('The integrity metadata for %s is malformed.', $what));
            }
            [$algorithm, $encoded] = $parts;
            $digest = base64_decode($encoded, true);

            if ($digest === false || $digest === '') {
                throw new TypeMetadataException(sprintf('The integrity metadata for %s carries a digest that is not base64.', $what));
            }
            $digestsByAlgorithm[$algorithm][] = $digest;
        }

        foreach (self::ALGORITHMS as $algorithm) {
            if (! isset($digestsByAlgorithm[$algorithm])) {
                continue;
            }
            $actual = hash($algorithm, $octets, true);

            foreach ($digestsByAlgorithm[$algorithm] as $expected) {
                if (hash_equals($expected, $actual)) {
                    return;
                }
            }

            throw new TypeMetadataException(sprintf('The %s does not match its %s integrity metadata.', $what, $algorithm));
        }

        throw new TypeMetadataException(sprintf(
            'The integrity metadata for %s uses no supported hash algorithm (sha256, sha384, sha512).',
            $what,
        ));
    }
}
