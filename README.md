# Certificate Chain Resolver

Resolve SSL/TLS certificate chains with a simple to use interface.

A hosted version using this package can be found here: https://cert.chief.app/chain.

## Installation

```bash
composer require stayallive/certificate-chain-resolver
```

## Usage

You can use `CertificateChain::fetchForCertificate` to retrieve the full PEM encoded chain as a string.

```php
$output = Stayallive\CertificateChain\CertificateChain::fetchForCertificate(
    Stayallive\CertificateChain\Certificate::loadFromPathOrUrl('path/to/certificate.pem')
)
```

You can use `Certificate::loadFromPathOrUrl` to retrieve a `Certificate` instance you need for constructing a `CertificateChain` instance.

The certificate is fetched using `file_get_contents` so any path or URL that is supported by `file_get_contents` should work.

The certificate can be in multiple formats and encodings, currently supported: PEM, DER and PKCS7.

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
