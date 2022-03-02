<?php

namespace Stayallive\CertificateChain\Exceptions;

final class CouldNotParseCertificate extends ResolverException
{
    public static function emptyContents(): self
    {
        return new self('Could not create a certificate from a empty string.');
    }

    public static function invalidContent(string $content): self
    {
        return new self("Could not create a certificate with content `{$content}`.");
    }
}
