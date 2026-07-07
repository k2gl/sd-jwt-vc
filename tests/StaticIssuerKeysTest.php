<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests;

use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use K2gl\SdJwtVc\StaticIssuerKeys;
use K2gl\SdJwtVc\Tests\Support\SdJwtVcTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(StaticIssuerKeys::class)]
final class StaticIssuerKeysTest extends SdJwtVcTestCase
{
    public function testResolvesADirectVerifier(): void
    {
        $verifier = self::draftIssuerVerifier();
        $keys = (new StaticIssuerKeys)->add('https://issuer.example', $verifier);

        self::assertSame($verifier, $keys->resolve('https://issuer.example', (object) []));
    }

    public function testSelectsFromAJwkSetByKid(): void
    {
        $keys = (new StaticIssuerKeys)->addJwks('https://issuer.example', [
            'keys' => [
                ['kid' => 'other', 'kty' => 'EC', 'crv' => 'P-256', 'x' => 'AA', 'y' => 'AA'],
                self::draftIssuerJwk() + ['kid' => 'doc-signer-05-25-2022'],
            ],
        ]);

        $verifier = $keys->resolve('https://issuer.example', (object) ['kid' => 'doc-signer-05-25-2022']);

        // The selected key must be the draft's: it verifies the draft example.
        self::assertTrue($verifier->verify(...self::draftSignedParts()));
    }

    public function testSingleKeySetNeedsNoKid(): void
    {
        $keys = (new StaticIssuerKeys)->addJwks('https://issuer.example', [
            'keys' => [self::draftIssuerJwk()],
        ]);

        self::assertTrue($keys->resolve('https://issuer.example', (object) [])->verify(...self::draftSignedParts()));
    }

    public function testMultipleKeysWithoutKidFail(): void
    {
        $keys = (new StaticIssuerKeys)->addJwks('https://issuer.example', [
            'keys' => [self::draftIssuerJwk(), self::draftIssuerJwk() + ['kid' => 'x']],
        ]);

        $this->expectException(IssuerKeyResolutionFailed::class);

        $keys->resolve('https://issuer.example', (object) []);
    }

    public function testUnknownKidFails(): void
    {
        $keys = (new StaticIssuerKeys)->addJwks('https://issuer.example', [
            'keys' => [self::draftIssuerJwk() + ['kid' => 'a']],
        ]);

        $this->expectException(IssuerKeyResolutionFailed::class);

        $keys->resolve('https://issuer.example', (object) ['kid' => 'b']);
    }

    public function testUnknownIssuerFails(): void
    {
        $this->expectException(IssuerKeyResolutionFailed::class);

        (new StaticIssuerKeys)->resolve('https://issuer.example', (object) []);
    }

    public function testNullIssuerFails(): void
    {
        $this->expectException(IssuerKeyResolutionFailed::class);

        (new StaticIssuerKeys)->resolve(null, (object) []);
    }

    /**
     * The draft example's Issuer-signed JWT, split for direct signature checks.
     *
     * @return array{string, string}
     */
    private static function draftSignedParts(): array
    {
        $jwt = explode('~', self::fixture('draft17/issuance-sd-jwt-vc.txt'))[0];
        $parts = explode('.', $jwt);
        $signature = base64_decode(strtr($parts[2], '-_', '+/') . str_repeat('=', (4 - strlen($parts[2]) % 4) % 4));
        self::assertNotFalse($signature);

        return [$parts[0] . '.' . $parts[1], $signature];
    }
}
