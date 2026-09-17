<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Exception;

/**
 * Type Metadata (draft-ietf-oauth-sd-jwt-vc Section 5) could not be retrieved
 * or is unusable: the document is malformed, fails its integrity check, names
 * another type, or the `extends` chain does not resolve. When a Verifier's
 * policy asks for Type Metadata, this rejects the credential (Section 5.7).
 */
final class TypeMetadataException extends SdJwtVcException {}
