<?php

namespace Stayallive\CertificateChain\Exceptions;

final class CouldNotLoadCertificate extends ResolverException
{
    public static function cannotGetContents(string $path): self
    {
        return new self("Could not create a certificate for path `{$path}`.");
    }
}
