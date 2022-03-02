<?php

namespace Stayallive\CertificateChain\Exceptions;

use Exception;

class CouldNotCreateCertificate extends Exception
{
    public static function emptyContents(): static
    {
        return new static('Could not create a certificate from a empty string.');
    }

    public static function invalidContent(string $content): static
    {
        return new static("Could not create a certificate with content `{$content}`.");
    }
}
