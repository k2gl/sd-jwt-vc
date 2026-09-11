<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use Closure;
use K2gl\SdJwt\Internal\HashAlgorithm;
use K2gl\SdJwt\Jws\JwsSigner;
use K2gl\SdJwt\Sd;
use K2gl\SdJwt\SdJwt;
use K2gl\SdJwt\SdJwtIssuer;
use K2gl\SdJwtVc\Exception\InvalidSdJwtVcException;
use stdClass;

/**
 * Issues SD-JWT VCs: a k2gl/sd-jwt {@see SdJwtIssuer} that stamps the
 * `dc+sd-jwt` typ header and enforces the credential payload rules — `vct`
 * is required, and the protected claims (`iss`, `exp`, `cnf`, `vct`,
 * `status`, ...) cannot be marked selectively disclosable, not even in
 * their sub-claims.
 *
 * ```php
 * $issuer = new SdJwtVcIssuer(JwsSigner::es256FromPem($pem));
 *
 * $credential = $issuer->issue([
 *     'vct' => 'https://credentials.example.com/identity_credential',
 *     'iss' => 'https://issuer.example.com',
 *     'iat' => time(),
 *     'cnf' => ['jwk' => $holderJwk],
 *     'given_name' => Sd::hide('John'),
 * ]);
 * ```
 */
final class SdJwtVcIssuer
{
    public const TYPE = 'dc+sd-jwt';

    private readonly SdJwtIssuer $inner;

    /**
     * @param ?Closure(): string $saltGenerator
     */
    public function __construct(
        JwsSigner $signer,
        string $hashAlgorithm = HashAlgorithm::DEFAULT,
        ?Closure $saltGenerator = null,
    ) {
        $this->inner = new SdJwtIssuer($signer, $hashAlgorithm, $saltGenerator);
    }

    /**
     * @param array<string, mixed>|stdClass $claims
     * @param array<string, mixed> $header Extra JOSE header parameters; `typ` is always `dc+sd-jwt`.
     */
    public function issue(array|stdClass $claims, array $header = []): SdJwt
    {
        $properties = $claims instanceof stdClass ? get_object_vars($claims) : $claims;

        $vct = $properties['vct'] ?? null;

        if (! is_string($vct) || $vct === '') {
            throw new InvalidSdJwtVcException('An SD-JWT VC requires a string "vct" claim.');
        }

        if (array_key_exists('aka_vcts', $properties) && ! $properties['aka_vcts'] instanceof Sd) {
            SdJwtVcVerifier::assertTypeList($properties['aka_vcts']);
        }

        foreach (SdJwtVcVerifier::PROTECTED_CLAIMS as $claim) {
            if (array_key_exists($claim, $properties) && self::containsMarker($properties[$claim])) {
                throw new InvalidSdJwtVcException(sprintf(
                    'The "%s" claim and its sub-claims must not be selectively disclosable.',
                    $claim,
                ));
            }
        }

        if (isset($header['typ']) && $header['typ'] !== self::TYPE) {
            throw new InvalidSdJwtVcException(sprintf('The "typ" header of an SD-JWT VC must be "%s".', self::TYPE));
        }

        return $this->inner->issue($claims, ['typ' => self::TYPE] + $header);
    }

    /** Whether a value, or anything nested in it, is marked selectively disclosable. */
    private static function containsMarker(mixed $value): bool
    {
        if ($value instanceof Sd) {
            return true;
        }

        if ($value instanceof stdClass) {
            $value = get_object_vars($value);
        }

        if (! is_array($value)) {
            return false;
        }

        foreach ($value as $item) {
            if (self::containsMarker($item)) {
                return true;
            }
        }

        return false;
    }
}
