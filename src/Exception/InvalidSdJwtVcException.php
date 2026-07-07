<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Exception;

/**
 * The SD-JWT VC violates a rule of draft-ietf-oauth-sd-jwt-vc: wrong `typ`,
 * missing or malformed `vct`, or a protected claim conveyed via a Disclosure.
 */
final class InvalidSdJwtVcException extends SdJwtVcException {}
