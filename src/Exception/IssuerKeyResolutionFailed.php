<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Exception;

/**
 * No permitted key discovery mechanism produced a validated Issuer key —
 * per draft-ietf-oauth-sd-jwt-vc Section 2.5 the credential MUST be rejected.
 */
final class IssuerKeyResolutionFailed extends SdJwtVcException {}
