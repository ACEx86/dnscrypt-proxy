# ![dnscrypt-proxy 2](https://raw.github.com/dnscrypt/dnscrypt-proxy/master/logo.png?3)

[![Financial Contributors on Open Collective](https://opencollective.com/dnscrypt/all/badge.svg?label=financial+contributors)](https://opencollective.com/dnscrypt)
[![DNSCrypt-Proxy Release](https://img.shields.io/github/release/dnscrypt/dnscrypt-proxy.svg?label=Latest%20Release&style=popout)](https://github.com/dnscrypt/dnscrypt-proxy/releases/latest)
[![Build Status](https://github.com/DNSCrypt/dnscrypt-proxy/actions/workflows/releases.yml/badge.svg)](https://github.com/DNSCrypt/dnscrypt-proxy/actions/workflows/releases.yml)

## Overview

A flexible DNS proxy, with support for modern encrypted DNS protocols such as [DNSCrypt v2](https://dnscrypt.info/protocol), [DNS-over-HTTPS](https://www.rfc-editor.org/rfc/rfc8484.txt), [Anonymized DNSCrypt](https://github.com/DNSCrypt/dnscrypt-protocol/blob/master/ANONYMIZED-DNSCRYPT.txt) and [ODoH (Oblivious DoH)](https://github.com/DNSCrypt/dnscrypt-resolvers/blob/master/v3/odoh-servers.md).

* **[dnscrypt-proxy documentation](https://dnscrypt.info/doc) ← Start here**
* [DNSCrypt project home page](https://dnscrypt.info/)
* [Discussions](https://github.com/DNSCrypt/dnscrypt-proxy/discussions)
* [DNS-over-HTTPS and DNSCrypt resolvers](https://dnscrypt.info/public-servers)
* [Server and client implementations](https://dnscrypt.info/implementations)
* [DNS stamps](https://dnscrypt.info/stamps)
* [FAQ](https://dnscrypt.info/faq)

## [Download the latest release](https://github.com/dnscrypt/dnscrypt-proxy/releases/latest)

Available as source code and pre-built binaries for most operating systems and architectures (see below).

## Features

* DNS traffic encryption and authentication. Supports DNS-over-HTTPS (DoH) using TLS 1.3 and QUIC, DNSCrypt, Anonymized DNS and ODoH
* Client IP addresses can be hidden using Tor, SOCKS proxies or Anonymized DNS relays
* DNS query monitoring, with separate log files for regular and suspicious queries
* Filtering: block ads, malware, and other unwanted content. Compatible with all DNS services
* Time-based filtering, with a flexible weekly schedule
* Transparent redirection of specific domains to specific resolvers
* DNS caching, to reduce latency and improve privacy
* Local IPv6 blocking to reduce latency on IPv4-only networks
* Load balancing: pick a set of resolvers, dnscrypt-proxy will automatically measure and keep track of their speed, and balance the traffic across the fastest available ones.
* Cloaking: like a `HOSTS` file on steroids, that can return preconfigured addresses for specific names, or resolve and return the IP address of other names. This can be used for local development as well as to enforce safe search results on Google, Yahoo, DuckDuckGo and Bing
* Automatic background updates of resolvers lists
* Can force outgoing connections to use TCP
* Compatible with DNSSEC
* Includes a local DoH server in order to support ECH (ESNI)

How to use these files, as well as how to verify their signatures, are documented in the [installation instructions](https://github.com/dnscrypt/dnscrypt-proxy/wiki/installation).

## Update & Build

cd dnscrypt-proxy/<br>
go get -u<br>
go mod tidy<br>
go mod vendor<br>
go build -ldflags="-s -w" -mod vendor
