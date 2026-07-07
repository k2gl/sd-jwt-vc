<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests;

use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use K2gl\SdJwtVc\StaticIssuerKeys;
use K2gl\SdJwtVc\Tests\Support\SdJwtVcTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(StaticIssuerKeys::class)]
final class StaticIssuerKeysTest extends SdJwtVcTestCase
{
    public function testResolvesADirectVerifier(): void
    {
        // arrange
        $verifier = self::draftIssuerVerifier();
        $keys = (new StaticIssuerKeys)->add('https://issuer.example', $verifier);

        // act
        $resolved = $keys->resolve('https://issuer.example', (object) []);

        // assert
        fact($resolved)->is($verifier);
    }

    public function testSelectsFromAJwkSetByKid(): void
    {
        // arrange
        $keys = (new StaticIssuerKeys)->addJwks('https://issuer.example', [
            'keys' => [
                ['kid' => 'other', 'kty' => 'EC', 'crv' => 'P-256', 'x' => 'AA', 'y' => 'AA'],
                self::draftIssuerJwk() + ['kid' => 'doc-signer-05-25-2022'],
            ],
        ]);

        // act
        $verifier = $keys->resolve('https://issuer.example', (object) ['kid' => 'doc-signer-05-25-2022']);

        // assert: the selected key must be the draft's — it verifies the draft example
        fact($verifier->verify(...self::draftSignedParts()))->true();
    }

    public function testSingleKeySetNeedsNoKid(): void
    {
        // arrange
        $keys = (new StaticIssuerKeys)->addJwks('https://issuer.example', [
            'keys' => [self::draftIssuerJwk()],
        ]);

        // act
        $verifier = $keys->resolve('https://issuer.example', (object) []);

        // assert
        fact($verifier->verify(...self::draftSignedParts()))->true();
    }

    public function testMultipleKeysWithoutKidFail(): void
    {
        // arrange
        $keys = (new StaticIssuerKeys)->addJwks('https://issuer.example', [
            'keys' => [self::draftIssuerJwk(), self::draftIssuerJwk() + ['kid' => 'x']],
        ]);

        // act + assert
        fact(static fn () => $keys->resolve('https://issuer.example', (object) []))
            ->throws(IssuerKeyResolutionFailed::class);
    }

    public function testUnknownKidFails(): void
    {
        // arrange
        $keys = (new StaticIssuerKeys)->addJwks('https://issuer.example', [
            'keys' => [self::draftIssuerJwk() + ['kid' => 'a']],
        ]);

        // act + assert
        fact(static fn () => $keys->resolve('https://issuer.example', (object) ['kid' => 'b']))
            ->throws(IssuerKeyResolutionFailed::class);
    }

    public function testUnknownIssuerFails(): void
    {
        // act + assert
        fact(static fn () => (new StaticIssuerKeys)->resolve('https://issuer.example', (object) []))
            ->throws(IssuerKeyResolutionFailed::class);
    }

    public function testNullIssuerFails(): void
    {
        // act + assert
        fact(static fn () => (new StaticIssuerKeys)->resolve(null, (object) []))
            ->throws(IssuerKeyResolutionFailed::class);
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
        fact($signature)->notFalse();

        return [$parts[0] . '.' . $parts[1], $signature];
    }
}
