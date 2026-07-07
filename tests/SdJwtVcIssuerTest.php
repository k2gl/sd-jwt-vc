<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests;

use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwt\Presentation;
use K2gl\SdJwt\Sd;
use K2gl\SdJwtVc\Exception\InvalidSdJwtVcException;
use K2gl\SdJwtVc\SdJwtVcIssuer;
use K2gl\SdJwtVc\SdJwtVcVerifier;
use K2gl\SdJwtVc\Tests\Support\SdJwtVcTestCase;
use PHPUnit\Framework\Attributes\CoversClass;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(SdJwtVcIssuer::class)]
final class SdJwtVcIssuerTest extends SdJwtVcTestCase
{
    public function testIssuesAVerifiableCredential(): void
    {
        // arrange
        $issuer = new SdJwtVcIssuer(self::localSigner());

        // act
        $credential = $issuer->issue([
            'vct' => 'urn:example:identity',
            'iss' => 'https://issuer.example',
            'given_name' => Sd::hide('John'),
            'family_name' => Sd::hide('Doe'),
        ]);
        $presented = Presentation::of($credential)->disclose('/given_name')->toCompact();
        $verified = (new SdJwtVcVerifier)->verifyPresentation(
            $presented,
            self::localVerifier(),
            KeyBinding::notRequired(),
        );

        // assert: the credential header
        fact($credential->header()->typ)->is('dc+sd-jwt');

        // assert: only the disclosed claim is visible after presentation
        fact($verified->vct())->is('urn:example:identity');
        fact($verified->claims()['given_name'])->is('John');
        fact($verified->claims())->arrayNotHasKey('family_name');
    }

    public function testExtraHeaderParametersSurvive(): void
    {
        // arrange
        $issuer = new SdJwtVcIssuer(self::localSigner());

        // act
        $credential = $issuer->issue(['vct' => 'urn:example:t'], ['kid' => 'key-7']);

        // assert
        fact($credential->header()->kid)->is('key-7');
        fact($credential->header()->typ)->is('dc+sd-jwt');
    }

    public function testDisclosableSubIsAllowed(): void
    {
        // arrange
        $issuer = new SdJwtVcIssuer(self::localSigner());

        // act
        $credential = $issuer->issue(['vct' => 'urn:example:t', 'sub' => Sd::hide('user-1')]);
        $verified = (new SdJwtVcVerifier)->verify($credential, self::localVerifier());

        // assert
        fact($verified->claims()['sub'])->is('user-1');
    }

    public function testMissingVctIsRejected(): void
    {
        // arrange
        $issuer = new SdJwtVcIssuer(self::localSigner());

        // act + assert
        fact(static fn () => $issuer->issue(['iss' => 'https://issuer.example']))
            ->throws(InvalidSdJwtVcException::class, 'vct');
    }

    public function testHiddenVctIsRejected(): void
    {
        // arrange
        $issuer = new SdJwtVcIssuer(self::localSigner());

        // act + assert
        fact(static fn () => $issuer->issue(['vct' => Sd::hide('urn:example:t')]))
            ->throws(InvalidSdJwtVcException::class);
    }

    public function testHiddenProtectedClaimIsRejected(): void
    {
        // arrange
        $issuer = new SdJwtVcIssuer(self::localSigner());

        // act + assert
        fact(static fn () => $issuer->issue(['vct' => 'urn:example:t', 'status' => Sd::hide(['x' => 1])]))
            ->throws(InvalidSdJwtVcException::class, 'status');
    }

    public function testForeignTypOverrideIsRejected(): void
    {
        // arrange
        $issuer = new SdJwtVcIssuer(self::localSigner());

        // act + assert
        fact(static fn () => $issuer->issue(['vct' => 'urn:example:t'], ['typ' => 'JWT']))
            ->throws(InvalidSdJwtVcException::class, 'typ');
    }
}
