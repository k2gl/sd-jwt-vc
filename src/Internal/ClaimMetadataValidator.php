<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Internal;

use K2gl\SdJwt\VerifiedSdJwt;
use K2gl\SdJwtVc\ClaimMetadata;
use K2gl\SdJwtVc\Exception\InvalidSdJwtVcException;

/**
 * Validation of a verified credential against the claim metadata of its type
 * (draft-ietf-oauth-sd-jwt-vc Section 5.6): every path must evaluate, and
 * every claim it selects must be selectively disclosable exactly as its `sd`
 * says — disclosable meaning directly represented as a Disclosure, not merely
 * inside one. An undisclosed array element was disclosable by definition.
 *
 * `mandatory` is not checked: a Verifier must not read the absence of a
 * selectively disclosable claim from a presentation as the Issuer having left
 * it out (Section 5.6.3).
 *
 * @internal
 */
final class ClaimMetadataValidator
{
    /**
     * @param list<ClaimMetadata> $claims
     */
    public static function validate(VerifiedSdJwt $verified, array $claims): void
    {
        $paths = new ClaimPath($verified->payload(), $verified->undisclosedPaths());
        $disclosed = array_fill_keys($verified->disclosedPaths(), true);

        foreach ($claims as $claim) {
            if ($claim->sd() === ClaimMetadata::SD_ALLOWED) {
                $paths->select($claim->path); // the path must still evaluate

                continue;
            }

            foreach ($paths->select($claim->path) as ['pointer' => $pointer, 'undisclosed' => $undisclosed]) {
                $disclosable = $undisclosed || isset($disclosed[$pointer]);

                if ($claim->sd() === ClaimMetadata::SD_ALWAYS && ! $disclosable) {
                    throw new InvalidSdJwtVcException(sprintf(
                        'The claim at %s must be selectively disclosable (Type Metadata says "sd": "always"), but it is not.',
                        $pointer,
                    ));
                }

                if ($claim->sd() === ClaimMetadata::SD_NEVER && $disclosable) {
                    throw new InvalidSdJwtVcException(sprintf(
                        'The claim at %s must not be selectively disclosable (Type Metadata says "sd": "never"), but it is.',
                        $pointer,
                    ));
                }
            }
        }
    }
}
