<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Internal;

use K2gl\Dsse\PublicKey;
use K2gl\Dsse\Verifier;
use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use Throwable;

/**
 * Key selection from a JWK Set (RFC 7517): by `kid` when the JWT header has
 * one, otherwise the set must contain exactly one key.
 *
 * @internal
 */
final class JwkSet
{
    /**
     * @param array<string, mixed> $jwks
     */
    public static function select(array $jwks, ?string $keyId): Verifier
    {
        $keys = $jwks['keys'] ?? null;

        if (! is_array($keys) || $keys === []) {
            throw new IssuerKeyResolutionFailed('The JWK Set has no "keys".');
        }

        if ($keyId !== null) {
            foreach ($keys as $key) {
                if (is_array($key) && ($key['kid'] ?? null) === $keyId) {
                    return self::toVerifier($key);
                }
            }

            // No kid matched; fall back to a sole kid-less key, a common
            // shape for single-key issuers.
            $hasAnyKid = array_filter($keys, static fn ($key): bool => is_array($key) && isset($key['kid']));

            if ($hasAnyKid !== [] || count($keys) !== 1) {
                throw new IssuerKeyResolutionFailed(sprintf('No key with kid "%s" in the JWK Set.', $keyId));
            }
        }

        if (count($keys) !== 1) {
            throw new IssuerKeyResolutionFailed(
                'The JWT has no "kid" header and the JWK Set contains more than one key.',
            );
        }

        $key = reset($keys);

        if (! is_array($key)) {
            throw new IssuerKeyResolutionFailed('Malformed key entry in the JWK Set.');
        }

        return self::toVerifier($key);
    }

    /**
     * @param array<mixed> $jwk
     */
    private static function toVerifier(array $jwk): Verifier
    {
        try {
            /** @var array<string, mixed> $jwk */
            return PublicKey::fromJwk($jwk);
        } catch (Throwable $e) {
            throw new IssuerKeyResolutionFailed('Unusable JWK in the JWK Set: ' . $e->getMessage(), previous: $e);
        }
    }
}
