# cert-fetcher

Fetch ssl certificates from https urls and store them in different formats.

## Supported output formats

- pem
- jks (java keystore)

## Print

Prints the certificates of a given URL.

```bash
cert-fetcher --url https://www.foo.bar

# All options
cert-fetcher --help
```

## Export pem

Stores the certificates from the given URL into a pem file.

```bash
cert-fetcher pem --url https://www.foo.bar

# All options
cert-fetcher pem --help
```

## Export java keystore

Stores the certificates from the given URL into a java keystore file.

```bash
cert-fetcher jks --url https://www.foo.bar

# All options
cert-fetcher jks --help
```