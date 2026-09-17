<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\SdJwt\VerifiedSdJwt;
use stdClass;

/**
 * A successfully verified SD-JWT VC: the Processed SD-JWT Payload plus
 * typed access to the credential-level claims.
 */
final class VerifiedSdJwtVc
{
    public function __construct(
        private readonly VerifiedSdJwt $inner,
        private readonly ?ResolvedTypeMetadata $typeMetadata = null,
    ) {}

    /**
     * The type's Type Metadata with its `extends` chain resolved and the
     * credential validated against it — when the verifier was given a
     * {@see TypeMetadataResolver}; null otherwise.
     */
    public function typeMetadata(): ?ResolvedTypeMetadata
    {
        return $this->typeMetadata;
    }

    /** The Verifiable Credential type (`vct` claim). */
    public function vct(): string
    {
        $vct = get_object_vars($this->inner->payload())['vct'] ?? null;

        return is_string($vct) ? $vct : '';
    }

    /**
     * Additional credential types the credential is also known as (`aka_vcts`).
     *
     * @return list<string>
     */
    public function alsoKnownAsTypes(): array
    {
        $types = get_object_vars($this->inner->payload())['aka_vcts'] ?? [];

        /** @var list<string> */
        return is_array($types) ? array_values($types) : [];
    }

    /** The `iss` claim, when present (may be conveyed via x5c instead). */
    public function issuer(): ?string
    {
        $issuer = get_object_vars($this->inner->payload())['iss'] ?? null;

        return is_string($issuer) ? $issuer : null;
    }

    /**
     * The `status` claim, for a status mechanism such as Token Status List
     * (k2gl/token-status-list reads it with `StatusReference::fromClaim()`).
     */
    public function status(): ?stdClass
    {
        $status = get_object_vars($this->inner->payload())['status'] ?? null;

        return $status instanceof stdClass ? $status : null;
    }

    /** The Processed SD-JWT Payload; JSON objects are stdClass instances. */
    public function payload(): stdClass
    {
        return $this->inner->payload();
    }

    /**
     * The Processed SD-JWT Payload as an associative array.
     *
     * @return array<string, mixed>
     */
    public function claims(): array
    {
        return $this->inner->claims();
    }

    /** The payload of the verified Key Binding JWT, when one was checked. */
    public function keyBindingPayload(): ?stdClass
    {
        return $this->inner->keyBindingPayload();
    }

    /**
     * JSON Pointers of the claims that arrived through Disclosures, array
     * positions as issued (see k2gl/sd-jwt).
     *
     * @return list<string>
     */
    public function disclosedPaths(): array
    {
        return $this->inner->disclosedPaths();
    }

    /**
     * JSON Pointers, as issued, of the array elements that were not disclosed.
     *
     * @return list<string>
     */
    public function undisclosedPaths(): array
    {
        return $this->inner->undisclosedPaths();
    }
}
