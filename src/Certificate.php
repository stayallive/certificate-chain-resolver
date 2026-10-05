<?php

namespace Stayallive\CertificateChain;

use RuntimeException;
use phpseclib4\File\CMS;
use phpseclib4\File\ASN1;
use phpseclib4\File\X509;
use phpseclib4\File\CMS\SignedData;
use phpseclib4\Exception\BaseException;
use Stayallive\CertificateChain\Exceptions\CouldNotLoadCertificate;
use Stayallive\CertificateChain\Exceptions\CouldNotParseCertificate;

class Certificate
{
    private X509 $certificate;

    /** @var array<string, mixed> */
    private array $parsedContents;

    /**
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotLoadCertificate
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotParseCertificate
     */
    public static function loadFromPathOrUrl(string $pathOrUrl): self
    {
        $contents = @file_get_contents($pathOrUrl);

        if ($contents === false) {
            throw CouldNotLoadCertificate::cannotGetContents($pathOrUrl);
        }

        return new self($contents);
    }

    /** @throws \Stayallive\CertificateChain\Exceptions\CouldNotParseCertificate */
    public function __construct(string $contents)
    {
        if (empty($contents)) {
            throw CouldNotParseCertificate::emptyContents();
        }

        $original = null;

        // If we are missing the pem certificate header, try to convert it to a PEM formatted string first
        if (str_starts_with($contents, '-----BEGIN PKCS7-----')) {
            $converted = $this->convertPkcs7EncodedBerToPem(
                $this->extractBerFromPem($contents),
            );

            if ($converted === null) {
                throw CouldNotParseCertificate::invalidContent($contents);
            }

            $original = $contents;
            $contents = $converted;
        } elseif (!str_starts_with($contents, '-----BEGIN CERTIFICATE-----')) {
            $original = $contents;

            // Extract from either a PKCS#7 format or DER formatted contents
            $contents = $this->convertPkcs7EncodedBerToPem($contents) ?? $this->convertDerEncodedToPem($contents);
        }

        try {
            $this->certificate    = X509::load($contents);
            $this->parsedContents = $this->certificate->toArray(true);
        } catch (BaseException) {
            throw CouldNotParseCertificate::invalidContent($original ?? $contents);
        }
    }

    public function __toString(): string
    {
        return $this->getContents();
    }

    public function getContents(): string
    {
        return $this->convertDerEncodedToPem(
            $this->certificate->toString(['binary' => true]),
        );
    }

    public function hasParentInTrustChain(): bool
    {
        return $this->getParentCertificateUrl() !== null;
    }

    /**
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotLoadCertificate
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotParseCertificate
     */
    public function fetchParentCertificate(): self
    {
        $parentCertUrl = $this->getParentCertificateUrl();

        if ($parentCertUrl === null) {
            throw new RuntimeException('Cannot fetch parent certificate for certificate without parent.');
        }

        return self::loadFromPathOrUrl($parentCertUrl);
    }

    public function getParentCertificateUrl(): ?string
    {
        $extensions = $this->parsedContents['tbsCertificate']['extensions'] ?? [];

        foreach ($extensions as $extension) {
            if ($extension['extnId'] === 'id-pe-authorityInfoAccess') {
                foreach ($extension['extnValue'] as $extnValue) {
                    if ($extnValue['accessMethod'] === 'id-ad-caIssuers') {
                        return $extnValue['accessLocation']['uniformResourceIdentifier'] ?? null;
                    }
                }
            }
        }

        return null;
    }

    private function extractBerFromPem(string $pem): string
    {
        $base64encoded = preg_replace('/(-----(BEGIN|END) ([A-Z0-9]+)-----)/', '', $pem);

        assert($base64encoded !== null);

        return base64_decode(
            str_replace("\n", '', trim($base64encoded)),
        );
    }

    private function convertDerEncodedToPem(string $der): string
    {
        $pem = chunk_split(base64_encode($der), 64, "\n");

        return "-----BEGIN CERTIFICATE-----\n{$pem}-----END CERTIFICATE-----\n";
    }

    private function convertPkcs7EncodedBerToPem(string $pkcs7): ?string
    {
        try {
            $signedData = CMS::load($pkcs7, ASN1::FORMAT_DER);
        } catch (BaseException) {
            return null;
        }

        // Make sure this is an PKCS#7 signedData object
        if (!$signedData instanceof SignedData) {
            return null;
        }

        $certificate = $signedData->getCertificates()[0] ?? null;

        if (!$certificate instanceof X509) {
            return null;
        }

        // Return the PEM encoded certificate
        return $this->convertDerEncodedToPem($certificate->toString(['binary' => true]));
    }
}
