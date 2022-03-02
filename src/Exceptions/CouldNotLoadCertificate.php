<?php

namespace Stayallive\CertificateChain\Exceptions;

use Exception;

class CouldNotLoadCertificate extends Exception
{
    public static function cannotGetContents(string $path): self
    {
        return new static("Could not create a certificate for path `{$path}`.");
    }
}
