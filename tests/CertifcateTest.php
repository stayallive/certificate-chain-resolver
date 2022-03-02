<?php

namespace Tests;

use RuntimeException;
use PHPUnit\Framework\TestCase;
use Stayallive\CertificateChain\Certificate;
use Stayallive\CertificateChain\CertificateChain;
use Stayallive\CertificateChain\Exceptions\CouldNotLoadCertificate;
use Stayallive\CertificateChain\Exceptions\CouldNotCreateCertificate;

class CertifcateTest extends TestCase
{
    public function testItThrowsExceptionOnInvalidCertificatePath(): void
    {
        $invalidPath = __DIR__ . '/invalid/path/to/cert.pem';

        $this->expectException(CouldNotLoadCertificate::class);
        $this->expectExceptionMessage("Could not create a certificate for path `{$invalidPath}`.");

        Certificate::loadFromPathOrUrl($invalidPath);
    }

    public function testItThrowsExceptionOnEmptyCertificateContents(): void
    {
        $this->expectException(CouldNotCreateCertificate::class);
        $this->expectExceptionMessage('Could not create a certificate from a empty string.');

        new Certificate('');
    }

    public function testItThrowsExceptionOnInvalidCertificateContents(): void
    {
        $this->expectException(CouldNotCreateCertificate::class);
        $this->expectExceptionMessage('Could not create a certificate with content `invalid_content`.');

        new Certificate('invalid_content');
    }

    public function testItThowsExceptionOnInvalidPkcs7CertificateString(): void
    {
        $invalidContents = '-----BEGIN PKCS7-----invalid_contents-----END PKCS7-----';

        $this->expectException(CouldNotCreateCertificate::class);
        $this->expectExceptionMessage("Could not create a certificate with content `{$invalidContents}`.");

        new Certificate($invalidContents);
    }

    public function testStaticHelperReturnsFullCertificateChainAsPemEncodedString(): void
    {
        $chainContents = CertificateChain::fetchForCertificate(
            Certificate::loadFromPathOrUrl(__DIR__ . '/fixtures/self-signed/cert.pem')
        );

        $this->assertStringEqualsFile(__DIR__ . '/fixtures/self-signed/chain.pem', $chainContents);
    }

    public function testItThrowsExceptionWhenLoadingParentCertificateForCertificateWithoutParent(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Cannot fetch parent certificate for certificate without parent.');

        $certificate = Certificate::loadFromPathOrUrl(__DIR__ . '/fixtures/self-signed/cert.pem');

        $certificate->fetchParentCertificate();
    }

    /** @dataProvider certificateTypeProvider */
    public function testItCanParseACertificateAndFetchTheFullChain(string $fixture, int $chainLength, string $certFile = 'cert.pem', string $chainFile = 'chain.pem'): void
    {
        $inputFile = __DIR__ . "/fixtures/{$fixture}/{$certFile}";

        $chain = new CertificateChain(
            Certificate::loadFromPathOrUrl($inputFile)
        );

        $this->assertCount($chainLength, $chain->getCertificates());
        $this->assertStringEqualsFile(__DIR__ . "/fixtures/{$fixture}/{$chainFile}", $chain->getContents());
    }

    private function certificateTypeProvider(): array
    {
        return [
            'pem::dv-letsencrypt-certchief' => ['dv-letsencrypt-certchief', 3],
            'pem::dv-thawte-google'         => ['dv-thawte-google', 2],
            'pem::ev-sectigo-coolblue'      => ['ev-sectigo-coolblue', 3],
            'pem::self-signed'              => ['self-signed', 1],
            'der::self-signed'              => ['self-signed', 1, 'cert.der'],
            'pkcs7 as pem::self-signed'     => ['self-signed', 1, 'cert.p7b'],
        ];
    }
}
