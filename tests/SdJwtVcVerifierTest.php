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

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(SdJwtVcVerifier::class)]
#[CoversClass(VerifiedSdJwtVc::class)]
final class SdJwtVcVerifierTest extends SdJwtVcTestCase
{
    public function testVerifiesTheDraftIssuanceExample(): void
    {
        // act
        $credential = $this->verifier()->verify(
            self::fixture('draft17/issuance-sd-jwt-vc.txt'),
            self::draftIssuerKeys(),
        );

        // assert: credential identity
        fact($credential->vct())->is('https://credentials.example.com/identity_credential');
        fact($credential->issuer())->is(self::DRAFT_ISSUER);
        fact($credential->status())->null();
        fact($credential->keyBindingPayload())->null();

        // assert: disclosed claims
        $claims = $credential->claims();
        fact($claims['given_name'])->is('John');
        fact($claims['is_over_18'])->true();
        fact($claims)->arrayNotHasKey('_sd');
    }

    public function testVerifiesTheDraftPresentationExample(): void
    {
        // act
        $credential = $this->verifier()->verifyPresentation(
            self::fixture('draft17/presentation-sd-jwt-vc-kb.txt'),
            self::draftIssuerKeys(),
            KeyBinding::required(audience: 'https://example.com/verifier', nonce: '1234567890'),
        );

        // assert: disclosed claims
        $claims = $credential->claims();
        fact($claims['is_over_65'])->true();
        fact($claims['address']['locality'])->is('Anytown');
        fact($claims)->arrayNotHasKey('given_name');

        // assert: key binding payload
        $keyBinding = $credential->keyBindingPayload();
        fact($keyBinding)->notNull();
        fact($keyBinding->iat)->is(1783345758);
    }

    public function testAcceptsADirectVerifierInsteadOfAResolver(): void
    {
        // act
        $credential = $this->verifier()->verify(
            self::fixture('draft17/issuance-sd-jwt-vc.txt'),
            self::draftIssuerVerifier(),
        );

        // assert
        fact($credential->vct())->is('https://credentials.example.com/identity_credential');
    }

    public function testLegacyTypIsAcceptedByDefault(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(['vct' => 'urn:example:t'], ['typ' => 'vc+sd-jwt']);

        // act
        $credential = $this->verifier()->verify($sdJwt, self::localVerifier());

        // assert
        fact($credential->vct())->is('urn:example:t');
    }

    public function testStatusClaimIsExposed(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue([
            'vct' => 'urn:example:t',
            'status' => ['status_list' => ['idx' => 0, 'uri' => 'https://x.example/status/1']],
        ], ['typ' => 'dc+sd-jwt']);

        // act
        $status = $this->verifier()->verify($sdJwt, self::localVerifier())->status();

        // assert
        fact($status)->notNull();
        fact($status->status_list->idx)->is(0);
    }

    public function testUnknownIssuerFailsResolution(): void
    {
        // act + assert
        fact(fn () => $this->verifier()->verify(
            self::fixture('draft17/issuance-sd-jwt-vc.txt'),
            new StaticIssuerKeys,
        ))->throws(IssuerKeyResolutionFailed::class);
    }

    public function testWrongTypIsRejected(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(['vct' => 'urn:example:t', 'iss' => 'https://x.example'], ['typ' => 'JWT']);

        // act + assert
        fact(fn () => $this->verifier()->verify($sdJwt, self::localVerifier()))
            ->throws(InvalidSdJwtVcException::class, 'typ');
    }

    public function testLegacyTypCanBeRefused(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(['vct' => 'urn:example:t'], ['typ' => 'vc+sd-jwt']);

        // act + assert
        fact(fn () => $this->verifier(acceptLegacyType: false)->verify($sdJwt, self::localVerifier()))
            ->throws(InvalidSdJwtVcException::class);
    }

    public function testMissingVctIsRejected(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(['iss' => 'https://x.example'], ['typ' => 'dc+sd-jwt']);

        // act + assert
        fact(fn () => $this->verifier()->verify($sdJwt, self::localVerifier()))
            ->throws(InvalidSdJwtVcException::class, 'vct');
    }

    public function testSelectivelyDisclosedProtectedClaimIsRejected(): void
    {
        // The base issuer happily hides "exp"; the VC layer must reject it.
        // arrange
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(
            ['vct' => 'urn:example:t', 'exp' => Sd::hide(PHP_INT_MAX)],
            ['typ' => 'dc+sd-jwt'],
        );

        // act + assert
        fact(fn () => $this->verifier()->verify($sdJwt, self::localVerifier()))
            ->throws(InvalidSdJwtVcException::class, 'exp');
    }

    public function testSelectivelyDisclosedVctIsRejected(): void
    {
        // arrange
        $issuer = new SdJwtIssuer(self::localSigner());
        $sdJwt = $issuer->issue(['vct' => Sd::hide('urn:example:t')], ['typ' => 'dc+sd-jwt']);

        // act + assert
        fact(fn () => $this->verifier()->verify($sdJwt, self::localVerifier()))
            ->throws(InvalidSdJwtVcException::class);
    }

    private function verifier(bool $acceptLegacyType = true): SdJwtVcVerifier
    {
        return new SdJwtVcVerifier(clock: self::DRAFT_CLOCK, acceptLegacyType: $acceptLegacyType);
    }
}
