<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests;

use K2gl\SdJwt\KeyBinding;
use K2gl\SdJwt\Presentation;
use K2gl\SdJwt\Sd;
use K2gl\SdJwt\SdJwt;
use K2gl\SdJwtVc\Exception\InvalidSdJwtVcException;
use K2gl\SdJwtVc\Exception\TypeMetadataException;
use K2gl\SdJwtVc\Internal\ClaimMetadataValidator;
use K2gl\SdJwtVc\Internal\ClaimPath;
use K2gl\SdJwtVc\ResolvedTypeMetadata;
use K2gl\SdJwtVc\SdJwtVcIssuer;
use K2gl\SdJwtVc\SdJwtVcVerifier;
use K2gl\SdJwtVc\StaticTypeMetadata;
use K2gl\SdJwtVc\Tests\Support\SdJwtVcTestCase;
use K2gl\SdJwtVc\VerifiedSdJwtVc;
use PHPUnit\Framework\Attributes\CoversClass;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * A credential validated against its type's claim metadata (Section 5.6),
 * using the draft's education credential (Appendix A.2): Figure 29's payload
 * issued with the selective disclosure Figure 30 prescribes.
 */
#[CoversClass(ClaimMetadataValidator::class)]
#[CoversClass(ClaimPath::class)]
#[CoversClass(SdJwtVcVerifier::class)]
#[CoversClass(VerifiedSdJwtVc::class)]
#[CoversClass(ResolvedTypeMetadata::class)]
#[CoversClass(StaticTypeMetadata::class)]
final class TypeMetadataValidationTest extends SdJwtVcTestCase
{
    private const VCT = 'https://betelgeuse.example.com/education_credential/v42';

    public function testTheDraftsCredentialPassesItsOwnTypeMetadata(): void
    {
        // arrange
        $presentation = Presentation::of(self::educationCredential())->discloseAll()->toCompact();

        // act
        $credential = self::verifier()->verifyPresentation($presentation, self::localVerifier(), KeyBinding::notRequired());

        // assert
        fact($credential->typeMetadata()?->vct())->is(self::VCT);
        fact($credential->typeMetadata()?->claims())->count(7);
        fact($credential->typeMetadata()?->display()[0]['locale'] ?? null)->is('en-US');
        fact($credential->claims()['degrees'])->count(3);
        fact($credential->disclosedPaths())->contains('/degrees/1/date_awarded');
    }

    public function testAWithheldArrayElementStillSatisfiesAlways(): void
    {
        // arrange — the second degree stays undisclosed; nothing below it is selected
        $presentation = Presentation::of(self::educationCredential())
            ->disclose('/name', '/address', '/address/street_address', '/degrees/0', '/degrees/0/date_awarded', '/degrees/2', '/degrees/2/date_awarded')
            ->toCompact();

        // act
        $credential = self::verifier()->verifyPresentation($presentation, self::localVerifier(), KeyBinding::notRequired());

        // assert
        fact($credential->claims()['degrees'])->count(2);
        fact($credential->undisclosedPaths())->is(['/degrees/1']);
    }

    public function testADisclosedElementWithoutItsDateStillPasses(): void
    {
        // arrange — date_awarded is "always": disclosable, whether or not the Holder discloses it
        $presentation = Presentation::of(self::educationCredential())
            ->disclose('/name', '/degrees/0')
            ->toCompact();

        // act
        $credential = self::verifier()->verifyPresentation($presentation, self::localVerifier(), KeyBinding::notRequired());

        // assert
        fact($credential->claims()['degrees'])->is([['field_of_study' => 'Intergalactic Politics']]);
    }

    public function testRejectsAClaimThatShouldHaveBeenDisclosable(): void
    {
        // arrange — name is "always", but was issued in the clear
        $credential = self::issue(['name' => 'Zaphod Beeblebrox'] + self::payloadWithSd(['name']));
        $presentation = Presentation::of($credential)->discloseAll()->toCompact();

        // act + assert
        fact(fn () => self::verifier()->verifyPresentation($presentation, self::localVerifier(), KeyBinding::notRequired()))->throws(
            InvalidSdJwtVcException::class,
            inspect: static fn (InvalidSdJwtVcException $e) => fact($e->getMessage())->containsString('/name must be selectively disclosable'),
        );
    }

    public function testRejectsAClaimThatMustNotBeDisclosable(): void
    {
        // arrange — degrees is "never", but was issued behind a Disclosure
        $payload = self::payloadWithSd(['name', 'address', 'address/street_address', 'degrees/*', 'degrees/*/date_awarded']);
        $payload['degrees'] = Sd::hide($payload['degrees']);
        $presentation = Presentation::of(self::issue($payload))->discloseAll()->toCompact();

        // act + assert
        fact(fn () => self::verifier()->verifyPresentation($presentation, self::localVerifier(), KeyBinding::notRequired()))->throws(
            InvalidSdJwtVcException::class,
            inspect: static fn (InvalidSdJwtVcException $e) => fact($e->getMessage())->containsString('/degrees must not be selectively disclosable'),
        );
    }

    public function testRejectsAnArrayElementSubClaimThatMustNotBeDisclosable(): void
    {
        // arrange — field_of_study inside the third degree is "never"
        $payload = self::payloadWithSd(['name', 'address', 'address/street_address', 'degrees/*', 'degrees/*/date_awarded']);
        $payload['degrees'][2] = Sd::hide(['field_of_study' => Sd::hide('Quantum Mechanics'), 'date_awarded' => Sd::hide('2016-07-25')]);
        $presentation = Presentation::of(self::issue($payload))->discloseAll()->toCompact();

        // act + assert
        fact(fn () => self::verifier()->verifyPresentation($presentation, self::localVerifier(), KeyBinding::notRequired()))->throws(
            InvalidSdJwtVcException::class,
            inspect: static fn (InvalidSdJwtVcException $e) => fact($e->getMessage())->containsString('/degrees/2/field_of_study must not'),
        );
    }

    public function testAPathIntoTheWrongShapeIsAnError(): void
    {
        // arrange — the type says name has a sub-claim, the credential has a string
        $registry = (new StaticTypeMetadata)->add(self::VCT, json_encode([
            'vct' => self::VCT,
            'claims' => [['path' => ['name', 'first'], 'sd' => 'allowed'], ['path' => ['address', 0], 'sd' => 'allowed']],
        ], JSON_THROW_ON_ERROR));
        $presentation = Presentation::of(self::educationCredential())->discloseAll()->toCompact();
        $verifier = new SdJwtVcVerifier(typeMetadata: $registry);

        // act + assert
        fact(static fn () => $verifier->verifyPresentation($presentation, self::localVerifier(), KeyBinding::notRequired()))->throws(
            InvalidSdJwtVcException::class,
            inspect: static fn (InvalidSdJwtVcException $e) => fact($e->getMessage())->containsString('not an object'),
        );
    }

    public function testAMissingClaimSelectsNothingAndPasses(): void
    {
        // arrange — metadata for claims the credential does not carry
        $registry = (new StaticTypeMetadata)->add(self::VCT, json_encode([
            'vct' => self::VCT,
            'claims' => [['path' => ['nickname'], 'sd' => 'always'], ['path' => ['degrees', 7, 'x'], 'sd' => 'never'], ['path' => ['address', 'planet'], 'sd' => 'never']],
        ], JSON_THROW_ON_ERROR));
        $presentation = Presentation::of(self::educationCredential())->discloseAll()->toCompact();

        // act
        $credential = (new SdJwtVcVerifier(typeMetadata: $registry))->verifyPresentation($presentation, self::localVerifier(), KeyBinding::notRequired());

        // assert
        fact($credential->typeMetadata()?->claims())->count(3);
    }

    public function testUsesTheVctIntegrityClaimOfTheCredential(): void
    {
        // arrange — the credential pins the document; a different one is served
        $document = self::fixture('draft19/type-metadata/figure-30-education-credential.json');
        $payload = self::payloadWithSd(['name', 'address', 'address/street_address', 'degrees/*', 'degrees/*/date_awarded']);
        $payload['vct#integrity'] = 'sha256-' . base64_encode(hash('sha256', $document, true));
        $presentation = Presentation::of(self::issue($payload))->discloseAll()->toCompact();
        $registry = (new StaticTypeMetadata)->add(self::VCT, self::standalone($document))->add('https://galaxy.example.com/galactic-education-credential/v2', '{"vct":"https://galaxy.example.com/galactic-education-credential/v2"}');

        // act + assert
        fact(fn () => (new SdJwtVcVerifier(typeMetadata: $registry))->verifyPresentation($presentation, self::localVerifier(), KeyBinding::notRequired()))->throws(
            TypeMetadataException::class,
            inspect: static fn (TypeMetadataException $e) => fact($e->getMessage())->containsString('integrity'),
        );
    }

    public function testWithoutAResolverTypeMetadataIsNotLookedAt(): void
    {
        $presentation = Presentation::of(self::educationCredential())->discloseAll()->toCompact();

        $credential = (new SdJwtVcVerifier)->verifyPresentation($presentation, self::localVerifier(), KeyBinding::notRequired());

        fact($credential->typeMetadata())->null();
    }

    public function testACredentialWhoseTypeMetadataCannotBeObtainedIsRejected(): void
    {
        // arrange
        $presentation = Presentation::of(self::educationCredential())->discloseAll()->toCompact();
        $verifier = new SdJwtVcVerifier(typeMetadata: new StaticTypeMetadata);

        // act + assert
        fact(static fn () => $verifier->verifyPresentation($presentation, self::localVerifier(), KeyBinding::notRequired()))
            ->throws(TypeMetadataException::class);
    }

    /** The draft's Figure 29 payload, issued with the selective disclosure Figure 30 prescribes. */
    private static function educationCredential(): SdJwt
    {
        return self::issue(self::payloadWithSd(['name', 'address', 'address/street_address', 'degrees/*', 'degrees/*/date_awarded']));
    }

    /**
     * Figure 29 with `Sd::hide()` applied at the given paths (`*` = every element).
     *
     * @param list<string> $hidden
     * @return array<string, mixed>
     */
    private static function payloadWithSd(array $hidden): array
    {
        /** @var array<string, mixed> $payload */
        $payload = json_decode(self::fixture('draft19/type-metadata/figure-29-payload.json'), true, flags: JSON_THROW_ON_ERROR);
        unset($payload['vct#integrity']);
        $hide = static fn (bool $on, mixed $value): mixed => $on ? Sd::hide($value) : $value;

        $degrees = [];

        foreach ($payload['degrees'] as $degree) {
            $degree['date_awarded'] = $hide(in_array('degrees/*/date_awarded', $hidden, true), $degree['date_awarded']);
            $degrees[] = $hide(in_array('degrees/*', $hidden, true), $degree);
        }
        $payload['degrees'] = $degrees;
        $payload['address']['street_address'] = $hide(in_array('address/street_address', $hidden, true), $payload['address']['street_address']);
        $payload['address'] = $hide(in_array('address', $hidden, true), $payload['address']);
        $payload['name'] = $hide(in_array('name', $hidden, true), $payload['name']);

        return $payload;
    }

    /** @param array<string, mixed> $payload */
    private static function issue(array $payload): SdJwt
    {
        return (new SdJwtVcIssuer(self::localSigner()))->issue(['iss' => 'https://betelgeuse.example.com'] + $payload);
    }

    /** Figure 30 as a type of its own: the galactic type it extends is not in the draft. */
    private static function standalone(string $document): string
    {
        $decoded = json_decode($document, true, flags: JSON_THROW_ON_ERROR);
        unset($decoded['extends'], $decoded['extends#integrity']);

        return json_encode($decoded, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    private static function verifier(): SdJwtVcVerifier
    {
        $registry = (new StaticTypeMetadata)->add(self::VCT, self::standalone(self::fixture('draft19/type-metadata/figure-30-education-credential.json')));

        return new SdJwtVcVerifier(typeMetadata: $registry);
    }
}
