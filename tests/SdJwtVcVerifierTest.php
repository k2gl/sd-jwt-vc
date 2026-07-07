<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests;

use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwt\Sd;
use K2gl\SdJwt\SdJwtIssuer;
use K2gl\SdJwtVc\Exception\InvalidSdJwtVcException;
use K2gl\SdJwtVc\Exception\IssuerKeyResolutionFailed;
use K2gl\SdJwtVc\SdJwtVcVerifier;
use K2gl\SdJwtVc\StaticIssuerKeys;
use K2gl\SdJwtVc\Tests\Support\SdJwtVcTestCase;
use K2gl\SdJwtVc\VerifiedSdJwtVc;
use PHPUnit\Framework\Attributes\CoversClass;

#[CoversClass(SdJwtVcVerifier::class)]
#[CoversClass(VerifiedSdJwtVc::class)]
final class SdJwtVcVerifierTest extends SdJwtVcTestCase
{
    private function verifier(bool $acceptLegacyType = true): SdJwtVcVerifier
    {
        return new SdJwtVcVerifier(clock: self::DRAFT_CLOCK, acceptLegacyType: $acceptLegacyType);
    }

    public function testVerifiesTheDraftIssuanceExample(): void
    {
        $credential = $this->verifier()->verify(
            self::fixture('draft17/issuance-sd-jwt-vc.txt'),
            self::draftIssuerKeys(),
        );

        self::assertSame('https://credentials.example.com/identity_credential', $credential->vct());
        self::assertSame(self::DRAFT_ISSUER, $credential->issuer());
        self::assertNull($credential->status());
        self::assertNull($credential->keyBindingPayload());

        $claims = $credential->claims();
        self::assertSame('John', $claims['given_name']);
        self::assertTrue($claims['is_over_18']);
        self::assertArrayNotHasKey('_sd', $claims);
    }

    public function testVerifiesTheDraftPresentationExample(): void
    {
        $credential = $this->verifier()->verifyPresentation(
            self::fixture('draft17/presentation-sd-jwt-vc-kb.txt'),
            self::draftIssuerKeys(),
            KeyBinding::required(audience: 'https://example.com/verifier', nonce: '1234567890'),
        );

        $claims = $credential->claims();
        self::assertTrue($claims['is_over_65']);
        self::assertSame('Anytown', $claims['address']['locality']);
        self::assertArrayNotHasKey('given_name', $claims);

        $keyBinding = $credential->keyBindingPayload();
        self::assertNotNull($keyBinding);
        self::assertSame(1783345758, $keyBinding->iat);
    }

    public function testAcceptsADirectVerifierInsteadOfAResolver(): void
    {
        $credential = $this->verifier()->verify(
            self::fixture('draft17/issuance-sd-jwt-vc.txt'),
            self::draftIssuerVerifier(),
        );

        self::assertSame('https://credentials.example.com/identity_credential', $credential->vct());
    }

    public function testUnknownIssuerFailsResolution(): void
    {
        $this->expectException(IssuerKeyResolutionFailed::class);

        $this->verifier()->verify(
            self::fixture('draft17/issuance-sd-jwt-vc.txt'),
            new StaticIssuerKeys,
        );
    }

    public function testWrongTypIsRejected(): void
    {
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(['vct' => 'urn:example:t', 'iss' => 'https://x.example'], ['typ' => 'JWT']);

        $this->expectException(InvalidSdJwtVcException::class);
        $this->expectExceptionMessage('typ');

        $this->verifier()->verify($sdJwt, self::localVerifier());
    }

    public function testLegacyTypIsAcceptedByDefault(): void
    {
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(['vct' => 'urn:example:t'], ['typ' => 'vc+sd-jwt']);

        self::assertSame('urn:example:t', $this->verifier()->verify($sdJwt, self::localVerifier())->vct());
    }

    public function testLegacyTypCanBeRefused(): void
    {
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(['vct' => 'urn:example:t'], ['typ' => 'vc+sd-jwt']);

        $this->expectException(InvalidSdJwtVcException::class);

        $this->verifier(acceptLegacyType: false)->verify($sdJwt, self::localVerifier());
    }

    public function testMissingVctIsRejected(): void
    {
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(['iss' => 'https://x.example'], ['typ' => 'dc+sd-jwt']);

        $this->expectException(InvalidSdJwtVcException::class);
        $this->expectExceptionMessage('vct');

        $this->verifier()->verify($sdJwt, self::localVerifier());
    }

    public function testSelectivelyDisclosedProtectedClaimIsRejected(): void
    {
        // The base issuer happily hides "exp"; the VC layer must reject it.
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(
            ['vct' => 'urn:example:t', 'exp' => Sd::hide(PHP_INT_MAX)],
            ['typ' => 'dc+sd-jwt'],
        );

        $this->expectException(InvalidSdJwtVcException::class);
        $this->expectExceptionMessage('exp');

        $this->verifier()->verify($sdJwt, self::localVerifier());
    }

    public function testSelectivelyDisclosedVctIsRejected(): void
    {
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(['vct' => Sd::hide('urn:example:t')], ['typ' => 'dc+sd-jwt']);

        $this->expectException(InvalidSdJwtVcException::class);

        $this->verifier()->verify($sdJwt, self::localVerifier());
    }

    public function testStatusClaimIsExposed(): void
    {
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue([
            'vct' => 'urn:example:t',
            'status' => ['status_list' => ['idx' => 0, 'uri' => 'https://x.example/status/1']],
        ], ['typ' => 'dc+sd-jwt']);

        $status = $this->verifier()->verify($sdJwt, self::localVerifier())->status();

        self::assertNotNull($status);
        self::assertSame(0, $status->status_list->idx);
    }
}
