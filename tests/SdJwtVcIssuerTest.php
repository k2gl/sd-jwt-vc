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

#[CoversClass(SdJwtVcIssuer::class)]
final class SdJwtVcIssuerTest extends SdJwtVcTestCase
{
    public function testIssuesAVerifiableCredential(): void
    {
        $issuer = new SdJwtVcIssuer(self::localSigner());

        $credential = $issuer->issue([
            'vct' => 'urn:example:identity',
            'iss' => 'https://issuer.example',
            'given_name' => Sd::hide('John'),
            'family_name' => Sd::hide('Doe'),
        ]);

        self::assertSame('dc+sd-jwt', $credential->header()->typ);

        $presented = Presentation::of($credential)->disclose('/given_name')->toCompact();
        $verified = (new SdJwtVcVerifier)->verifyPresentation(
            $presented,
            self::localVerifier(),
            KeyBinding::notRequired(),
        );

        self::assertSame('urn:example:identity', $verified->vct());
        self::assertSame('John', $verified->claims()['given_name']);
        self::assertArrayNotHasKey('family_name', $verified->claims());
    }

    public function testExtraHeaderParametersSurvive(): void
    {
        $issuer = new SdJwtVcIssuer(self::localSigner());
        $credential = $issuer->issue(['vct' => 'urn:example:t'], ['kid' => 'key-7']);

        self::assertSame('key-7', $credential->header()->kid);
        self::assertSame('dc+sd-jwt', $credential->header()->typ);
    }

    public function testMissingVctIsRejected(): void
    {
        $issuer = new SdJwtVcIssuer(self::localSigner());

        $this->expectException(InvalidSdJwtVcException::class);
        $this->expectExceptionMessage('vct');

        $issuer->issue(['iss' => 'https://issuer.example']);
    }

    public function testHiddenVctIsRejected(): void
    {
        $issuer = new SdJwtVcIssuer(self::localSigner());

        $this->expectException(InvalidSdJwtVcException::class);

        $issuer->issue(['vct' => Sd::hide('urn:example:t')]);
    }

    public function testHiddenProtectedClaimIsRejected(): void
    {
        $issuer = new SdJwtVcIssuer(self::localSigner());

        $this->expectException(InvalidSdJwtVcException::class);
        $this->expectExceptionMessage('status');

        $issuer->issue(['vct' => 'urn:example:t', 'status' => Sd::hide(['x' => 1])]);
    }

    public function testForeignTypOverrideIsRejected(): void
    {
        $issuer = new SdJwtVcIssuer(self::localSigner());

        $this->expectException(InvalidSdJwtVcException::class);
        $this->expectExceptionMessage('typ');

        $issuer->issue(['vct' => 'urn:example:t'], ['typ' => 'JWT']);
    }

    public function testDisclosableSubIsAllowed(): void
    {
        $issuer = new SdJwtVcIssuer(self::localSigner());
        $credential = $issuer->issue(['vct' => 'urn:example:t', 'sub' => Sd::hide('user-1')]);

        $verified = (new SdJwtVcVerifier)->verify($credential, self::localVerifier());

        self::assertSame('user-1', $verified->claims()['sub']);
    }
}
