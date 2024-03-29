[![GoDoc](https://godoc.org/github.com/bakito/cert-fetcher?status.svg)](http://godoc.org/github.com/bakito/cert-fetcher)
[![Go](https://github.com/bakito/cert-fetcher/actions/workflows/go.yml/badge.svg)](https://github.com/bakito/cert-fetcher/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/bakito/cert-fetcher)](https://goreportcard.com/report/github.com/bakito/cert-fetcher)
[![GitHub Release](https://img.shields.io/github/release/bakito/cert-fetcher.svg?style=flat)](https://github.com/bakito/cert-fetcher/releases)

# cert-fetcher

Fetch ssl certificates from https urls and store them in different formats.

## Supported output formats

- pem
- jks (java keystore)

## Print

Prints the certificates of a given URL.

```bash
cert-fetcher https://www.foo.bar

# All options
cert-fetcher --help
```

## Export pem

Stores the certificates from the given URL into a pem file.

```bash
cert-fetcher pem https://www.foo.bar

# All options
cert-fetcher pem --help
```

## Export java keystore

Stores the certificates from the given URL into a java keystore file.

```bash
cert-fetcher jks https://www.foo.bar

# All options
cert-fetcher jks --help
```

### Run behind proxy

To run cert-fetcher behind a proxy, just provide the proxy as env variable.

```bash
env https_proxy=http://proxy.net:8080 cert-fetcher jks --url https://www.foo.bar
```
