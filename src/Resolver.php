<?php

namespace Stayallive\CertificateChain;

class Resolver
{
    /** @var array<int, \Stayallive\CertificateChain\Certificate> */
    private array $certificates;

    /**
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotLoadCertificate
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotParseCertificate
     */
    public static function fetchForCertificate(Certificate $certificate): string
    {
        return (string)new self($certificate);
    }

    /**
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotLoadCertificate
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotParseCertificate
     */
    public function __construct(Certificate $certificate)
    {
        $this->certificates = [$certificate];

        while (($lastCertificate = end($this->certificates)) && $lastCertificate->hasParentInTrustChain()) {
            $this->certificates[] = $lastCertificate->fetchParentCertificate();
        }
    }

    public function __toString(): string
    {
        return $this->getContents();
    }

    public function getContents(): string
    {
        return $this->formatAsChain($this->getCertificates());
    }

    public function getContentsWithoutOriginal(): string
    {
        return $this->formatAsChain($this->getCertificatesWithoutOriginal());
    }

    /** @return array<int, \Stayallive\CertificateChain\Certificate> */
    public function getCertificates(): array
    {
        return $this->certificates;
    }

    /** @return array<int, \Stayallive\CertificateChain\Certificate> */
    public function getCertificatesWithoutOriginal(): array
    {
        return array_slice($this->certificates, 1);
    }

    /** @param array<int, \Stayallive\CertificateChain\Certificate> $certificates */
    private function formatAsChain(array $certificates): string
    {
        return implode('', array_map(static fn (Certificate $certificate) => (string)$certificate, $certificates));
    }
}
