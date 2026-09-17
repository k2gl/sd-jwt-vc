<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests;

use K2gl\SdJwtVc\ClaimMetadata;
use K2gl\SdJwtVc\Exception\TypeMetadataException;
use K2gl\SdJwtVc\Internal\Integrity;
use K2gl\SdJwtVc\ResolvedTypeMetadata;
use K2gl\SdJwtVc\StaticTypeMetadata;
use K2gl\SdJwtVc\Tests\Support\SdJwtVcTestCase;
use K2gl\SdJwtVc\TypeMetadata;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * The Type Metadata document (Section 5.2), integrity metadata (Section 6) and
 * the `extends` chain (Sections 5.4–5.6.5), on the draft's own examples.
 */
#[CoversClass(TypeMetadata::class)]
#[CoversClass(ClaimMetadata::class)]
#[CoversClass(ResolvedTypeMetadata::class)]
#[CoversClass(StaticTypeMetadata::class)]
#[CoversClass(Integrity::class)]
#[CoversClass(TypeMetadataException::class)]
final class TypeMetadataTest extends SdJwtVcTestCase
{
    private const EDUCATION = 'https://betelgeuse.example.com/education_credential/v42';

    private const GALACTIC = 'https://galaxy.example.com/galactic-education-credential/v2';

    public function testReadsTheDraftsExampleDocument(): void
    {
        $metadata = TypeMetadata::fromJson(self::typeMetadataFixture('figure-30-education-credential.json'));

        fact($metadata->vct)->is(self::EDUCATION);
        fact($metadata->name)->is('Betelgeuse Education Credential - First Version');
        fact($metadata->extends)->is(self::GALACTIC);
        fact($metadata->extendsIntegrity)->is('sha256-ilOUJsTultOwLfz7QUcFALaRa3BP/jelX1ds04kB9yU=');
        fact(array_column($metadata->display ?? [], 'locale'))->is(['en-US', 'de-DE']);
        fact($metadata->claims)->count(7);
        fact($metadata->claims[0]->path)->is(['name']);
        fact($metadata->claims[0]->sd())->is('always');
        fact($metadata->claims[0]->mandatory())->true();
        fact($metadata->claims[1]->mandatory())->false();
        fact($metadata->claims[2]->svgId)->is('address_street_address');
        fact($metadata->claims[4]->path)->is(['degrees', null]);
        fact($metadata->raw()['display'][0]['rendering']['simple']['background_color'])->is('#12107c');
    }

    public function testDefaultsAndUnknownProperties(): void
    {
        $metadata = TypeMetadata::fromArray(['vct' => 'urn:example:t', 'x-custom' => 1, 'claims' => [['path' => ['a'], 'x' => 2]]]);

        fact($metadata->display)->null();
        fact($metadata->claims[0]->sd())->is('allowed');
        fact($metadata->claims[0]->mandatory())->false();
        fact($metadata->raw()['x-custom'])->is(1);
    }

    #[TestWith([['name' => 'no vct']])]
    #[TestWith([['vct' => '']])]
    #[TestWith([['vct' => 'urn:t', 'extends#integrity' => 'sha256-AA==']])]
    #[TestWith([['vct' => 'urn:t', 'extends' => 7]])]
    #[TestWith([['vct' => 'urn:t', 'display' => 'yes']])]
    #[TestWith([['vct' => 'urn:t', 'display' => [['name' => 'no locale']]]])]
    #[TestWith([['vct' => 'urn:t', 'claims' => 'yes']])]
    #[TestWith([['vct' => 'urn:t', 'claims' => [['path' => []]]]])]
    #[TestWith([['vct' => 'urn:t', 'claims' => [['path' => ['a', -1]]]]])]
    #[TestWith([['vct' => 'urn:t', 'claims' => [['path' => ['a', 1.5]]]]])]
    #[TestWith([['vct' => 'urn:t', 'claims' => [['path' => ['a'], 'sd' => 'sometimes']]]])]
    #[TestWith([['vct' => 'urn:t', 'claims' => [['path' => ['a'], 'mandatory' => 'yes']]]])]
    #[TestWith([['vct' => 'urn:t', 'claims' => [['path' => ['a'], 'display' => [['label' => 'no locale']]]]]])]
    #[TestWith([['vct' => 'urn:t', 'claims' => [['path' => ['a'], 'svg_id' => '1st']]]])]
    #[TestWith([['vct' => 'urn:t', 'claims' => [['path' => ['a'], 'svg_id' => 'x'], ['path' => ['b'], 'svg_id' => 'x']]]])]
    public function testRejectsAMalformedDocument(array $document): void
    {
        fact(static fn () => TypeMetadata::fromArray($document))->throws(TypeMetadataException::class);
    }

    public function testRejectsDocumentsThatAreNotJsonObjects(): void
    {
        fact(static fn () => TypeMetadata::fromJson('not json'))->throws(TypeMetadataException::class);
        fact(static fn () => TypeMetadata::fromJson('[1]'))->throws(TypeMetadataException::class);
    }

    public function testIntegrityAcceptsAMatchingDigestOfTheStrongestSupportedAlgorithm(): void
    {
        $octets = '{"vct":"urn:t"}';
        $sha256 = 'sha256-' . base64_encode(hash('sha256', $octets, true));
        $sha512 = 'sha512-' . base64_encode(hash('sha512', $octets, true));
        $wrong512 = 'sha512-' . base64_encode(str_repeat("\x00", 64));

        Integrity::verify($octets, $sha256, 'doc');
        Integrity::verify($octets, "$sha256 $sha512", 'doc');
        Integrity::verify($octets, "$wrong512 $sha512?some-option", 'doc'); // any digest of the strongest algorithm
        Integrity::verify($octets, "sha1-AAAA $sha256", 'doc');             // unsupported ones are ignored

        // a matching weaker digest does not rescue a mismatching stronger one
        fact(static fn () => Integrity::verify($octets, "$sha256 $wrong512", 'doc'))->throws(TypeMetadataException::class);
    }

    #[TestWith(['sha256-' . 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='])]
    #[TestWith(['sha1-AAAA'])]
    #[TestWith(['md5-AAAA sha1-BBBB'])]
    #[TestWith(['sha256'])]
    #[TestWith(['sha256-'])]
    #[TestWith(['sha256-not*base64'])]
    #[TestWith([''])]
    public function testIntegrityRejectsMismatchedUnsupportedOrMalformedMetadata(string $integrity): void
    {
        fact(static fn () => Integrity::verify('{"vct":"urn:t"}', $integrity, 'doc'))->throws(TypeMetadataException::class);
    }

    public function testStaticRegistryChecksIntegrityAndType(): void
    {
        // arrange
        $json = '{"vct":"urn:example:t","name":"T"}';
        $registry = (new StaticTypeMetadata)->add('urn:example:t', $json)->add('urn:example:liar', $json);
        $good = 'sha256-' . base64_encode(hash('sha256', $json, true));

        // act + assert
        fact($registry->resolve('urn:example:t', $good)->name)->is('T');
        fact($registry->resolve('urn:example:t', null)->name)->is('T');
        fact(static fn () => $registry->resolve('urn:example:t', 'sha256-' . base64_encode(str_repeat('x', 32))))->throws(TypeMetadataException::class);
        fact(static fn () => $registry->resolve('urn:example:liar', null))->throws(TypeMetadataException::class);
        fact(static fn () => $registry->resolve('urn:example:unknown', null))->throws(TypeMetadataException::class);
    }

    public function testExtendsProducesTheDraftsEffectiveClaims(): void
    {
        // arrange — Figures 20 and 21
        $registry = (new StaticTypeMetadata)
            ->add('https://example.com/base-type-metadata', self::typeMetadataFixture('figure-20-base-type.json'))
            ->add('https://example.com/custom-type-metadata', self::typeMetadataFixture('figure-21-child-type.json'));

        // act
        $resolved = ResolvedTypeMetadata::resolve($registry, 'https://example.com/custom-type-metadata', null);

        // assert — Figure 22
        $expected = json_decode(self::typeMetadataFixture('figure-22-effective-claims.json'), true)['claims'];
        $actual = array_map(
            static fn (ClaimMetadata $claim): array => ['path' => $claim->path, 'display' => $claim->display],
            $resolved->claims(),
        );

        fact($actual)->is($expected);
        fact(array_map(static fn (TypeMetadata $m): string => $m->vct, $resolved->chain()))
            ->is(['https://example.com/custom-type-metadata', 'https://example.com/base-type-metadata']);
        fact($resolved->vct())->is('https://example.com/custom-type-metadata');
    }

    public function testExtendsIntegrityIsCheckedOnTheExtendedDocument(): void
    {
        // arrange
        $base = '{"vct":"urn:base"}';
        $registry = (new StaticTypeMetadata)->add('urn:base', $base);
        $good = 'sha256-' . base64_encode(hash('sha256', $base, true));
        $registry->add('urn:child', json_encode(['vct' => 'urn:child', 'extends' => 'urn:base', 'extends#integrity' => $good], JSON_THROW_ON_ERROR));
        $registry->add('urn:child-bad', json_encode(['vct' => 'urn:child-bad', 'extends' => 'urn:base', 'extends#integrity' => 'sha256-' . base64_encode(str_repeat('y', 32))], JSON_THROW_ON_ERROR));

        // act + assert
        fact(ResolvedTypeMetadata::resolve($registry, 'urn:child', null)->chain())->count(2);
        fact(static fn () => ResolvedTypeMetadata::resolve($registry, 'urn:child-bad', null))->throws(TypeMetadataException::class);
    }

    public function testACircularChainIsRefused(): void
    {
        // arrange
        $registry = (new StaticTypeMetadata)
            ->add('urn:a', '{"vct":"urn:a","extends":"urn:b"}')
            ->add('urn:b', '{"vct":"urn:b","extends":"urn:c"}')
            ->add('urn:c', '{"vct":"urn:c","extends":"urn:a"}');

        // act + assert
        fact(static fn () => ResolvedTypeMetadata::resolve($registry, 'urn:a', null))->throws(
            TypeMetadataException::class,
            inspect: static fn (TypeMetadataException $e) => fact($e->getMessage())->containsString('extends itself'),
        );
    }

    public function testATooDeepChainIsRefused(): void
    {
        // arrange — a chain longer than the limit, no cycle
        $registry = new StaticTypeMetadata;

        for ($i = 0; $i <= ResolvedTypeMetadata::MAX_DEPTH; $i++) {
            $registry->add("urn:t$i", json_encode(['vct' => "urn:t$i", 'extends' => 'urn:t' . ($i + 1)], JSON_THROW_ON_ERROR));
        }
        $registry->add('urn:t' . (ResolvedTypeMetadata::MAX_DEPTH + 1), '{"vct":"urn:t9"}');

        // act + assert
        fact(static fn () => ResolvedTypeMetadata::resolve($registry, 'urn:t0', null))->throws(
            TypeMetadataException::class,
            inspect: static fn (TypeMetadataException $e) => fact($e->getMessage())->containsString('deeper than'),
        );
    }

    public function testAnExtensionCannotLoosenSdOrMandatory(): void
    {
        // arrange
        $base = json_encode(['vct' => 'urn:base', 'claims' => [
            ['path' => ['a'], 'sd' => 'always'],
            ['path' => ['b'], 'sd' => 'never'],
            ['path' => ['c'], 'mandatory' => true],
            ['path' => ['d']],
        ]], JSON_THROW_ON_ERROR);
        $registry = (new StaticTypeMetadata)->add('urn:base', $base)
            ->add('urn:ok', json_encode(['vct' => 'urn:ok', 'extends' => 'urn:base', 'claims' => [
                ['path' => ['a'], 'sd' => 'always', 'mandatory' => true],
                ['path' => ['c']],
                ['path' => ['d'], 'sd' => 'never', 'mandatory' => true],
            ]], JSON_THROW_ON_ERROR))
            ->add('urn:sd', json_encode(['vct' => 'urn:sd', 'extends' => 'urn:base', 'claims' => [['path' => ['a'], 'sd' => 'never']]], JSON_THROW_ON_ERROR))
            ->add('urn:sd2', json_encode(['vct' => 'urn:sd2', 'extends' => 'urn:base', 'claims' => [['path' => ['b'], 'sd' => 'allowed']]], JSON_THROW_ON_ERROR))
            ->add('urn:mandatory', json_encode(['vct' => 'urn:mandatory', 'extends' => 'urn:base', 'claims' => [['path' => ['c'], 'mandatory' => false]]], JSON_THROW_ON_ERROR));

        // act
        $ok = ResolvedTypeMetadata::resolve($registry, 'urn:ok', null)->claims();

        // assert
        fact(array_map(static fn (ClaimMetadata $c): array => [$c->path, $c->sd(), $c->mandatory()], $ok))->is([
            [['a'], 'always', true],
            [['b'], 'never', false],
            [['c'], 'allowed', true],
            [['d'], 'never', true],
        ]);
        fact(static fn () => ResolvedTypeMetadata::resolve($registry, 'urn:sd', null))->throws(TypeMetadataException::class);
        fact(static fn () => ResolvedTypeMetadata::resolve($registry, 'urn:sd2', null))->throws(TypeMetadataException::class);
        fact(static fn () => ResolvedTypeMetadata::resolve($registry, 'urn:mandatory', null))->throws(TypeMetadataException::class);
    }

    public function testDisplayComesFromTheNearestTypeThatDefinesIt(): void
    {
        // arrange
        $registry = (new StaticTypeMetadata)
            ->add('urn:base', '{"vct":"urn:base","display":[{"locale":"en","name":"Base"},{"locale":"de","name":"Basis"}]}')
            ->add('urn:mid', '{"vct":"urn:mid","extends":"urn:base"}')
            ->add('urn:top', '{"vct":"urn:top","extends":"urn:mid","display":[{"locale":"fr","name":"Sommet"}]}');

        // act + assert
        fact(ResolvedTypeMetadata::resolve($registry, 'urn:mid', null)->display())->is([['locale' => 'en', 'name' => 'Base'], ['locale' => 'de', 'name' => 'Basis']]);
        fact(ResolvedTypeMetadata::resolve($registry, 'urn:top', null)->display())->is([['locale' => 'fr', 'name' => 'Sommet']]);
        fact(ResolvedTypeMetadata::resolve((new StaticTypeMetadata)->add('urn:none', '{"vct":"urn:none"}'), 'urn:none', null)->display())->null();
    }

    protected static function typeMetadataFixture(string $name): string
    {
        return self::fixture('draft19/type-metadata/' . $name);
    }
}
