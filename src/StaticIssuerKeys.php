<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\Dsse\Verifier;
use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use K2gl\SdJwtVc\Internal\JwkSet;
use stdClass;

/**
 * Issuer keys pinned in configuration: the simplest (and offline) key
 * discovery mechanism, for when the Verifier already knows its trusted
 * Issuers.
 *
 * ```php
 * $keys = (new StaticIssuerKeys)
 *     ->add('https://issuer.example.com', PublicKey::fromPem($pem))
 *     ->addJwks('https://other.example.com', $jwkSet); // kid-aware
 * ```
 */
final class StaticIssuerKeys implements IssuerKeyResolver
{
    /** @var array<string, Verifier> */
    private array $verifiers = [];

    /** @var array<string, array<string, mixed>> */
    private array $jwkSets = [];

    public function add(string $issuer, Verifier $verifier): self
    {
        $this->verifiers[$issuer] = $verifier;

        return $this;
    }

    /**
     * @param array<string, mixed> $jwks A JWK Set: `{"keys": [...]}`.
     */
    public function addJwks(string $issuer, array $jwks): self
    {
        $this->jwkSets[$issuer] = $jwks;

        return $this;
    }

    public function resolve(?string $issuer, stdClass $header): Verifier
    {
        if ($issuer === null) {
            throw new IssuerKeyResolutionFailed('The SD-JWT VC has no "iss" claim to select a pinned key by.');
        }

        if (isset($this->verifiers[$issuer])) {
            return $this->verifiers[$issuer];
        }

        if (isset($this->jwkSets[$issuer])) {
            $keyId = $header->kid ?? null;

            return JwkSet::select($this->jwkSets[$issuer], is_string($keyId) ? $keyId : null);
        }

        throw new IssuerKeyResolutionFailed(sprintf('No pinned key for Issuer "%s".', $issuer));
    }
}
