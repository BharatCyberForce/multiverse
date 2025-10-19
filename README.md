# Multiverse
This tool is for multi uses

## Features

* Add `http://` to lines
* Remove duplicate lines
* Extract domain / strip path
* Parse `user:pass@host` patterns 
* Filter by domain extension 
* Remove `http://`/`https://` and paths
* Reverse IP Lookup
* ASN to IP
* CIDR to IP range 

## Quick start

1. Install Rust (if needed):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

2. Clone repo

```bash
git clone https://github.com/BharatCyberForce/multiverse
cd multiverse
```

3. `Cargo.toml`

Add these deps under `[dependencies]`

```toml
regex = "1"
ipnetwork = "0.20"
serde_json = "1"
reqwest = { version = "0.11", features = ["blocking", "json"] }
```

4. Build

```bash
cargo build --release
```

Binary: `target/release/multiverse`

## Usage

Run the binary:

```bash
./multiverse
```

Example flows (short):

* Add http to list:

  * choose `1`, `In:` `sites.txt`, `Out:` `sites_http.txt`

* Remove dupes:

  * choose `2`, `In:` `sites_http.txt`, `Out:` `uniq.txt`

* Extract domain only:

  * choose `3`, `In:` `sites_http.txt`, `Out:` `domains.txt`

* Reverse IP lookup (single IP or file):

  * choose `7`, `IP/File:` `1.2.3.4` or `ips.txt`, `Out:` `revip.txt`

* ASN -> prefixes:

  * choose `8`, `ASN/File:` `AS1234` or `asns.txt`, `Out:` `prefixes.txt`

* CIDR -> IP range:

  * choose `9`, `In:` `cidrs.txt`, `Out:` `ranges.txt`


## Cargo profile

```
	cargo build --release

	./multiverse
```
