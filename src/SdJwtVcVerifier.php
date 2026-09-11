<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc;

use K2gl\Dsse\Verifier;
use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwt\SdJwt;
use K2gl\SdJwt\SdJwtVerifier;
use K2gl\SdJwt\VerifiedSdJwt;
use K2gl\SdJwtVc\Exception\InvalidSdJwtVcException;
use stdClass;

/**
 * Verifies SD-JWT VCs per draft-ietf-oauth-sd-jwt-vc: RFC 9901 processing
 * (delegated to k2gl/sd-jwt) plus the VC rules — `typ` header, required
 * `vct`, protected claims that must never arrive via Disclosures — with the
 * Issuer key produced by a key discovery mechanism ({@see IssuerKeyResolver})
 * or pinned directly.
 *
 * ```php
 * $verifier = new SdJwtVcVerifier;
 *
 * $credential = $verifier->verifyPresentation(
 *     $compact,
 *     new JwtVcIssuerMetadata($httpClient, $requestFactory),
 *     KeyBinding::required(audience: 'https://verifier.example.org', nonce: $nonce),
 * );
 *
 * $credential->vct();     // e.g. "https://credentials.example.com/identity_credential"
 * $credential->claims();  // the Processed SD-JWT Payload
 * ```
 */
final class SdJwtVcVerifier
{
    /** Claims that, sub-claims included, MUST NOT be selectively disclosed (Section 2.2.2.2). */
    public const PROTECTED_CLAIMS = ['iss', 'nbf', 'exp', 'cnf', 'vct', 'vct#integrity', 'aka_vcts', 'status'];

    private readonly SdJwtVerifier $inner;

    /**
     * @param list<string> $allowedAlgorithms
     * @param list<string> $allowedHashAlgorithms
     * @param ?int $clock Unix time for `exp`/`nbf`/KB `iat` checks; defaults to time()
     * @param bool $acceptLegacyType Also accept the pre-2024 `vc+sd-jwt` typ. Draft -19
     *     dropped the transition period, so this is off by default.
     */
    public function __construct(
        array $allowedAlgorithms = SdJwtVerifier::DEFAULT_ALGORITHMS,
        array $allowedHashAlgorithms = SdJwtVerifier::DEFAULT_HASH_ALGORITHMS,
        ?int $clock = null,
        int $clockLeewaySeconds = 0,
        private readonly bool $acceptLegacyType = false,
    ) {
        $this->inner = new SdJwtVerifier(
            allowedAlgorithms: $allowedAlgorithms,
            allowedHashAlgorithms: $allowedHashAlgorithms,
            clock: $clock,
            clockLeewaySeconds: $clockLeewaySeconds,
        );
    }

    /**
     * Verify an SD-JWT VC as received from the Issuer (no Key Binding JWT).
     */
    public function verify(SdJwt|string $sdJwtVc, IssuerKeyResolver|Verifier $issuerKeys): VerifiedSdJwtVc
    {
        [$sdJwtVc, $issuerKey] = $this->prepare($sdJwtVc, $issuerKeys);

        return $this->checked($sdJwtVc, $this->inner->verify($sdJwtVc, $issuerKey));
    }

    /**
     * Verify a presentation of an SD-JWT VC: an SD-JWT+KB when Key Binding
     * is required by the Verifier's policy, otherwise a plain SD-JWT.
     */
    public function verifyPresentation(
        SdJwt|string $presentation,
        IssuerKeyResolver|Verifier $issuerKeys,
        KeyBinding $keyBinding,
    ): VerifiedSdJwtVc {
        [$presentation, $issuerKey] = $this->prepare($presentation, $issuerKeys);

        return $this->checked($presentation, $this->inner->verifyPresentation($presentation, $issuerKey, $keyBinding));
    }

    /**
     * @return array{SdJwt, Verifier}
     */
    private function prepare(SdJwt|string $sdJwtVc, IssuerKeyResolver|Verifier $issuerKeys): array
    {
        if (is_string($sdJwtVc)) {
            $sdJwtVc = SdJwt::parse($sdJwtVc);
        }

        $header = $sdJwtVc->header();
        $this->checkType($header);

        if ($issuerKeys instanceof Verifier) {
            return [$sdJwtVc, $issuerKeys];
        }

        $issuer = get_object_vars($sdJwtVc->payload())['iss'] ?? null;

        return [$sdJwtVc, $issuerKeys->resolve(is_string($issuer) ? $issuer : null, $header)];
    }

    private function checkType(stdClass $header): void
    {
        $type = $header->typ ?? null;
        $accepted = $this->acceptLegacyType ? ['dc+sd-jwt', 'vc+sd-jwt'] : ['dc+sd-jwt'];

        if (! is_string($type) || ! in_array($type, $accepted, true)) {
            throw new InvalidSdJwtVcException(sprintf(
                'The "typ" header must be %s, got %s.',
                implode(' or ', array_map(static fn (string $t): string => '"' . $t . '"', $accepted)),
                is_string($type) ? '"' . $type . '"' : 'none',
            ));
        }
    }

    /** The SD-JWT VC payload rules of Section 2.2.2. */
    private function checked(SdJwt $sdJwtVc, VerifiedSdJwt $verified): VerifiedSdJwtVc
    {
        $processed = get_object_vars($verified->payload());

        $vct = $processed['vct'] ?? null;

        if (! is_string($vct) || $vct === '') {
            throw new InvalidSdJwtVcException('The required "vct" claim is missing or not a string.');
        }

        if (array_key_exists('aka_vcts', $processed)) {
            self::assertTypeList($processed['aka_vcts']);
        }

        foreach ($verified->disclosedPaths() as $path) {
            foreach (self::PROTECTED_CLAIMS as $claim) {
                if ($path === '/' . $claim || str_starts_with($path, '/' . $claim . '/')) {
                    throw new InvalidSdJwtVcException(sprintf(
                        'The "%s" claim and its sub-claims must not be selectively disclosed (found "%s").',
                        $claim,
                        $path,
                    ));
                }
            }
        }

        return new VerifiedSdJwtVc($verified);
    }

    /**
     * `aka_vcts` (Section 2.2.2.2): additional credential types, a list of
     * non-empty strings.
     *
     * @internal shared with the issuer
     */
    public static function assertTypeList(mixed $value): void
    {
        if (! is_array($value) || ! array_is_list($value)) {
            throw new InvalidSdJwtVcException('The "aka_vcts" claim must be an array of credential types.');
        }

        foreach ($value as $type) {
            if (! is_string($type) || $type === '') {
                throw new InvalidSdJwtVcException('The "aka_vcts" claim must be an array of non-empty strings.');
            }
        }
    }
}
