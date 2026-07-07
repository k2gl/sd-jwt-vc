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
 * `status`, ...) cannot be marked selectively disclosable.
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

        foreach (SdJwtVcVerifier::PROTECTED_CLAIMS as $claim) {
            if (($properties[$claim] ?? null) instanceof Sd) {
                throw new InvalidSdJwtVcException(sprintf(
                    'The "%s" claim must not be selectively disclosable.',
                    $claim,
                ));
            }
        }

        if (isset($header['typ']) && $header['typ'] !== self::TYPE) {
            throw new InvalidSdJwtVcException(sprintf('The "typ" header of an SD-JWT VC must be "%s".', self::TYPE));
        }

        return $this->inner->issue($claims, ['typ' => self::TYPE] + $header);
    }
}
