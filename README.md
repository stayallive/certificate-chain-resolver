# Certificate Chain Resolver

[![Latest Version](https://img.shields.io/github/release/stayallive/certificate-chain-resolver.svg?style=flat-square)](https://github.com/stayallive/certificate-chain-resolver/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/github/workflow/status/stayallive/certificate-chain-resolver/ci/master.svg?style=flat-square)](https://github.com/stayallive/certificate-chain-resolver/actions/workflows/ci.yaml)
[![Total Downloads](https://img.shields.io/packagist/dt/stayallive/certificate-chain-resolver.svg?style=flat-square)](https://packagist.org/packages/stayallive/certificate-chain-resolver)

Resolve a certificate chain with a simple to use interface.

A hosted version using this package can be found here: https://cert.chief.app/chain.

## Installation

```bash
composer require stayallive/certificate-chain-resolver
```

## Usage

You can use `Resolver::fetchForCertificate` to retrieve the full PEM encoded chain as a string.

```php
$output = \Stayallive\CertificateChain\Resolver::fetchForCertificate(
    \Stayallive\CertificateChain\Certificate::loadFromPathOrUrl('path/to/certificate.pem')
);
```

You can use `Certificate::loadFromPathOrUrl` to retrieve a `Certificate` instance you need for constructing a `Resolver` instance.

The certificate is fetched using `file_get_contents` so any path or URL that is supported by `file_get_contents` should work.

The `Certificate` can be in multiple formats and encodings, currently supported: PEM, DER and PKCS7, they are all normalized to PEM encoding.

If you need the chain without the original certificate or want to get an array of `Certificate` instances representing the chain you can use the `Resolver` class directly:

```php
$chain = new \Stayallive\CertificateChain\Resolver(
    \Stayallive\CertificateChain\Certificate::loadFromPathOrUrl('path/to/certificate.pem')
);

$chain->getContents(); // Same as `Resolver::fetchForCertificate`, returns a string
$chain->getCertificates(); // Array of certificates in the chain, returns an array

// Versions that do not include the certificate that was used to construct the `Resolver` with
$chain->getContentsWithoutOriginal();
$chain->getCertificatesWithoutOriginal();
```

There are 2 possible exception that can be thrown while retrieving the certificate or it's chain:
- `CouldNotLoadCertificate` - this indicates fetching the certificate from an URL or path failed
- `CouldNotParseCertificate` - this indicates parsing the fetched certificate failed because it's invalid or it's encoding is unsupported

## Background: the trust chain

All operating systems contain a set of default trusted root certificates. But Certificate Authorities usually don't use their root certificate to sign customer certificates.
Instead of they use so called intermediate certificates, because they can be rotated more frequently.

A certificate can contain a special Authority Information Access extension (RFC-3280) with URL to issuer's certificate. Most browsers can use the AIA extension to download
missing intermediate certificate to complete the certificate chain. This is the exact meaning of the Extra download message. But some clients, mostly mobile browsers, don't
support this extension, so they report such certificate as untrusted.

This results in 'untrusted'-warnings since the browser thinks you are on an insecure connection.

A server should always send a complete chain, which means concatenated all certificates from the certificate to the trusted root certificate (exclusive, in this order), to
prevent such issues. So when installing a SSL certificate on a server you should install all intermediate certificates as well. You should be able to fetch intermediate
certificates from the issuer and concat them together by yourself.

This package helps you automatize that boring task by looping over certificate's AIA extension field and returning the full chain to you.

## Credits

This package was originally created as a fork of [ssl-certificate-chain-resolver](https://github.com/spatie/ssl-certificate-chain-resolver) written
by [Spatie](https://github.com/spatie) which was inspired by [cert-chain-resolver](https://github.com/zakjan/cert-chain-resolver/) written by [Jan Žák](http://www.zakjan.cz/).
Some text, mainly the background about the trust chain, was copied from the readme of his repo.

## Security Vulnerabilities

If you discover a security vulnerability within this package, please send an e-mail to Alex Bouma at `alex+security@bouma.me`. All security vulnerabilities will be swiftly
addressed.

## License

This package is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT).
