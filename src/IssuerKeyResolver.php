<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\Dsse\Verifier;
use stdClass;

/**
 * A key discovery and validation mechanism (draft-ietf-oauth-sd-jwt-vc
 * Section 2.5): given the `iss` claim value (may be null when conveyed by
 * other means, e.g. x5c) and the JOSE header of the Issuer-signed JWT,
 * produce the verified Issuer key or throw
 * {@see Exception\IssuerKeyResolutionFailed}.
 */
interface IssuerKeyResolver
{
    public function resolve(?string $issuer, stdClass $header): Verifier;
}
