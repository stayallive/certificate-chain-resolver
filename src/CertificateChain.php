<?php

namespace Stayallive\CertificateChain;

class CertificateChain
{
    /** @var array<int, \Stayallive\CertificateChain\Certificate> */
    protected array $certificates;

    /**
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotCreateCertificate
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotLoadCertificate
     */
    public static function fetchForCertificate(Certificate $certificate): string
    {
        return (string)new static($certificate);
    }

    /**
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotCreateCertificate
     * @throws \Stayallive\CertificateChain\Exceptions\CouldNotLoadCertificate
     */
    public function __construct(
        Certificate $certificate
    ) {
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
        return implode('', array_map(static fn (Certificate $certificate) => (string)$certificate, $this->certificates));
    }

    /** @return array<int, \Stayallive\CertificateChain\Certificate> */
    public function getCertificates(): array
    {
        return $this->certificates;
    }
}
