<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests\Support;

use K2gl\Dsse\PublicKey;
use K2gl\Dsse\Verifier;
use K2gl\SdJwt\Jws\JwsSigner;
use K2gl\SdJwtVc\StaticIssuerKeys;
use PHPUnit\Framework\TestCase;

abstract class SdJwtVcTestCase extends TestCase
{
    /** The KB-JWT of the draft example is issued at 1783345758. */
    protected const DRAFT_CLOCK = 1783345800;

    protected const DRAFT_ISSUER = 'https://example.com/issuer';

    protected static function fixture(string $relativePath): string
    {
        $contents = file_get_contents(__DIR__ . '/../fixtures/' . $relativePath);
        self::assertNotFalse($contents);

        return trim($contents);
    }

    /**
     * @return array<string, mixed>
     */
    protected static function draftIssuerJwk(): array
    {
        /** @var array<string, mixed> */
        return json_decode(self::fixture('draft17/issuer-public-key.jwk.json'), true);
    }

    /** The draft example's Issuer keys, kid-addressable as in its Figure 13. */
    protected static function draftIssuerKeys(): StaticIssuerKeys
    {
        return (new StaticIssuerKeys)->addJwks(self::DRAFT_ISSUER, [
            'keys' => [self::draftIssuerJwk() + ['kid' => 'doc-signer-05-25-2022']],
        ]);
    }

    protected static function draftIssuerVerifier(): Verifier
    {
        return PublicKey::fromJwk(self::draftIssuerJwk());
    }

    /** A locally generated P-256 signing key (self-contained, not the draft's). */
    protected static function localSigner(): JwsSigner
    {
        return JwsSigner::es256FromPem(self::localKey()['pem']);
    }

    protected static function localVerifier(): Verifier
    {
        return PublicKey::fromPem(self::localKey()['public']);
    }

    /**
     * @return array{pem: string, public: string}
     */
    protected static function localKey(): array
    {
        static $key = null;

        if ($key === null) {
            $resource = openssl_pkey_new([
                'curve_name' => 'prime256v1',
                'private_key_type' => OPENSSL_KEYTYPE_EC,
            ]);
            self::assertNotFalse($resource);
            openssl_pkey_export($resource, $pem);
            $details = openssl_pkey_get_details($resource);
            self::assertNotFalse($details);

            $key = ['pem' => (string) $pem, 'public' => (string) $details['key']];
        }

        return $key;
    }
}
