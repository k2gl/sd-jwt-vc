<?php

declare(strict_types=1);

namespace K2gl\SdJwtVc\Tests;

use K2gl\SdJwtVc\Exception\TypeMetadataException;
use K2gl\SdJwtVc\HttpTypeMetadata;
use K2gl\SdJwtVc\Internal\HttpDocument;
use K2gl\SdJwtVc\Tests\Support\SdJwtVcTestCase;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(HttpTypeMetadata::class)]
#[CoversClass(HttpDocument::class)]
final class HttpTypeMetadataTest extends SdJwtVcTestCase
{
    private const VCT = 'https://betelgeuse.example.com/education_credential/v42';

    public function testFetchesTheDocumentFromTheVctUrl(): void
    {
        // arrange
        $document = self::fixture('draft19/type-metadata/figure-30-education-credential.json');
        $resolver = $this->resolver([self::VCT => new Response(200, ['Content-Type' => 'application/json; charset=utf-8'], $document)]);
        $integrity = 'sha256-' . base64_encode(hash('sha256', $document, true));

        // act
        $metadata = $resolver->resolve(self::VCT, $integrity);

        // assert
        fact($metadata->vct)->is(self::VCT);
        fact($metadata->claims)->count(7);
    }

    public function testFollowsARedirectAndChecksIntegrityOnWhatArrived(): void
    {
        // arrange
        $document = '{"vct":"' . self::VCT . '"}';
        $resolver = $this->resolver([
            self::VCT => new Response(302, ['Location' => 'https://cdn.example.com/types/v42.json']),
            'https://cdn.example.com/types/v42.json' => new Response(200, ['Content-Type' => 'application/json'], $document),
        ]);

        // act + assert
        fact($resolver->resolve(self::VCT, null)->vct)->is(self::VCT);
        fact(static fn () => $resolver->resolve(self::VCT, 'sha256-' . base64_encode(str_repeat('z', 32))))->throws(TypeMetadataException::class);
    }

    public function testRejectsTheWrongMediaTypeAStatusErrorAndAnotherType(): void
    {
        // arrange
        $resolver = $this->resolver([
            'https://a.example.com/t' => new Response(200, ['Content-Type' => 'text/html'], '{"vct":"https://a.example.com/t"}'),
            'https://b.example.com/t' => new Response(404, ['Content-Type' => 'application/json'], '{}'),
            'https://c.example.com/t' => new Response(200, ['Content-Type' => 'application/json'], '{"vct":"https://c.example.com/other"}'),
            'https://d.example.com/t' => new Response(200, ['Content-Type' => 'application/json'], '[]'),
        ]);

        // act + assert
        foreach (['a', 'b', 'c', 'd'] as $host) {
            fact(static fn () => $resolver->resolve("https://$host.example.com/t", null))->throws(TypeMetadataException::class);
        }
    }

    public function testOnlyHttpsTypesAreFetched(): void
    {
        $resolver = $this->resolver([]);

        fact(static fn () => $resolver->resolve('urn:example:identity', null))->throws(TypeMetadataException::class);
        fact(static fn () => $resolver->resolve('http://example.com/t', null))->throws(TypeMetadataException::class);
        fact(static fn () => $resolver->resolve('https://example.com/t#frag', null))->throws(TypeMetadataException::class);
    }

    public function testTheBodyIsCapped(): void
    {
        // arrange
        $big = '{"vct":"' . self::VCT . '","description":"' . str_repeat('x', 5000) . '"}';
        $resolver = $this->resolver([self::VCT => new Response(200, ['Content-Type' => 'application/json'], $big)], maxBytes: 1024);

        // act + assert
        fact(static fn () => $resolver->resolve(self::VCT, null))->throws(
            TypeMetadataException::class,
            inspect: static fn (TypeMetadataException $e) => fact($e->getMessage())->containsString('larger than'),
        );
    }

    /** @param array<string, Response> $responses */
    private function resolver(array $responses, int $maxBytes = 1024 * 1024): HttpTypeMetadata
    {
        $client = $this->createStub(ClientInterface::class);
        $client->method('sendRequest')->willReturnCallback(
            static fn (RequestInterface $request): Response => $responses[(string) $request->getUri()] ?? new Response(404),
        );

        return new HttpTypeMetadata($client, new Psr17Factory, self::urlPolicy(), maxBytes: $maxBytes);
    }
}
