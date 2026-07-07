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
    public function __construct(private readonly VerifiedSdJwt $inner) {}

    /** The Verifiable Credential type (`vct` claim). */
    public function vct(): string
    {
        $vct = get_object_vars($this->inner->payload())['vct'] ?? null;

        return is_string($vct) ? $vct : '';
    }

    /** The `iss` claim, when present (may be conveyed via x5c instead). */
    public function issuer(): ?string
    {
        $issuer = get_object_vars($this->inner->payload())['iss'] ?? null;

        return is_string($issuer) ? $issuer : null;
    }

    /** The `status` claim for a status mechanism such as Token Status List. */
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
}
