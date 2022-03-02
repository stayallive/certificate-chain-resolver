<?php

namespace Stayallive\CertificateChain;

use RuntimeException;
use phpseclib3\File\ASN1;
use phpseclib3\File\X509;
use Stayallive\CertificateChain\Exceptions\CouldNotLoadCertificate;
use Stayallive\CertificateChain\Exceptions\CouldNotParseCertificate;

class Certificate
{
    private X509 $parser;

    private mixed $parsedContents;

    /**
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotLoadCertificate
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotParseCertificate
     */
    public static function loadFromPathOrUrl(string $pathOrUrl): static
    {
        $contents = @file_get_contents($pathOrUrl);

        if ($contents === false) {
            throw CouldNotLoadCertificate::cannotGetContents($pathOrUrl);
        }

        return new static($contents);
    }

    /**
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotParseCertificate
     */
    public function __construct(string $contents)
    {
        if (empty($contents)) {
            throw CouldNotParseCertificate::emptyContents();
        }

        $original = null;

        // If we are missing the pem certificate header, try to convert it to a PEM formatted string first
        if (str_starts_with($contents, '-----BEGIN PKCS7-----')) {
            $converted = $this->convertPkcs7EncodedBerToPem(
                $this->extractBerFromPem($contents)
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

        $this->parser = new X509;

        $this->parsedContents = $this->parser->loadX509($contents);

        if ($this->parsedContents === false) {
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
            $this->parser->saveX509($this->parsedContents, X509::FORMAT_DER)
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
    public function fetchParentCertificate(): static
    {
        $parentCertUrl = $this->getParentCertificateUrl();

        if ($parentCertUrl === null) {
            throw new RuntimeException('Cannot fetch parent certificate for certificate without parent.');
        }

        return static::loadFromPathOrUrl($parentCertUrl);
    }

    public function getParentCertificateUrl(): ?string
    {
        foreach ($this->parsedContents['tbsCertificate']['extensions'] as $extension) {
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
        return base64_decode(
            str_replace("\n", '', trim(preg_replace('/(-----(BEGIN|END) ([A-Z0-9]+)-----)/', '', $pem)))
        );
    }

    private function convertDerEncodedToPem(string $der): string
    {
        $pem = chunk_split(base64_encode($der), 64, "\n");

        return "-----BEGIN CERTIFICATE-----\n{$pem}-----END CERTIFICATE-----\n";
    }

    private function convertPkcs7EncodedBerToPem(string $pkcs7): ?string
    {
        $decoded = ASN1::decodeBER($pkcs7);
        $data    = $decoded[0]['content'] ?? [];

        // Make sure we are dealing with actual data
        if (empty($data) || is_string($data)) {
            return null;
        }

        // Make sure this is an PKCS#7 signedData object
        if ($data[0]['type'] === ASN1::TYPE_OBJECT_IDENTIFIER && $data[0]['content'] === '1.2.840.113549.1.7.2') {
            // Loop over all the content in the signedData object
            foreach ($data[1]['content'] as $pkcs7SignedData) {
                // Find all sequences of data
                if ($pkcs7SignedData['type'] === ASN1::TYPE_SEQUENCE) {
                    // Extract the sequence identifier if possible
                    $identifier = $pkcs7SignedData['content'][2] ?? '';

                    // Make sure the sequence is a PKCS#7 data object we are dealing with
                    if ($identifier['type'] === ASN1::TYPE_SEQUENCE && $identifier['content'][0]['content'] === '1.2.840.113549.1.7.1') {
                        // Extract the certificate data
                        $certificate = $pkcs7SignedData['content'][3];

                        // Extract the raw certificate data from the PKCS#7 string
                        $rawCert = substr($pkcs7, $certificate['start'] + $certificate['headerlength'], $certificate['length'] - $certificate['headerlength']);

                        // Return the PEM encoded certificate
                        return $this->convertDerEncodedToPem($rawCert);
                    }
                }
            }
        }

        return null;
    }
}
