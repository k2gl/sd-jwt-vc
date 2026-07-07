<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Exception;

use K2gl\SdJwt\Exception\SdJwtException;

/**
 * Base class for every exception thrown by this package. It extends the
 * k2gl/sd-jwt base exception, so a single `catch (SdJwtException)` covers
 * the whole verification pipeline.
 */
class SdJwtVcException extends SdJwtException {}
