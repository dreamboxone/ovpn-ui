# Bundled acme.sh

`acme.sh` here is the vendored Let's Encrypt / ACME client, embedded into the panel
binary via `//go:embed build/acme/acme.sh` (see main.go) and written out by
`vpn-ui install-acme <path>`.

## Why it is bundled

`obtain_letsencrypt_cert` in `vpn-ui.sh` used to acquire the client at runtime with
`curl https://get.acme.sh | sh`. On a box with no outbound access (or blocked DNS /
firewalled egress to get.acme.sh) that fetch fails, and the deploy printed:

    warning: acme.sh not found after install, skipping real SSL.

silently dropping to plain HTTP. Bundling the client makes real SSL work offline:
the menu extracts this copy and runs its `--install` locally (no network), and only
the final `--issue` reaches out to Let's Encrypt (which needs egress regardless).

## Pinned version

- Upstream: https://github.com/acmesh-official/acme.sh
- Tag: `3.1.4`
- sha256: `fcabf274d4f96966ec933879ae0257266e8ef2f7d16161f14b84dd896c0cac32`

## `dnsapi/dns_cf.sh`

The Cloudflare DNS-01 hook, from the same tag, bundled for the same reason as the
client itself and written out beside `acme.sh` by `vpn-ui install-acme <path>`.

- sha256: `9628ee8238cb3f9cfa1b1a985c0e9593436a3e4f8a9d65a6f775b981be9e76c8`

`acme.sh --install` copies a `dnsapi/` directory sitting next to it into
`$HOME/.acme.sh/dnsapi/`, which is where `_findHook` looks at issue time. Without
the file on disk 3.1.4 does not fetch it: `--dns dns_cf` fails with "Cannot find DNS
API hook", and the operator is told to add the TXT record by hand. That is why the
DNS-01 path (Cloudflare token, and every wildcard certificate) needs it vendored.

No other plugin is bundled: HTTP-01 standalone and DNS-01 via Cloudflare are the
only two challenges the menu offers, and neither `deploy/` nor `notify/` is used.

## Updating

Fetch the new tag's raw files, drop them in place, and refresh the tag + sha256s
above:

    curl -fsSL https://raw.githubusercontent.com/acmesh-official/acme.sh/<tag>/acme.sh \
        -o build/acme/acme.sh
    curl -fsSL https://raw.githubusercontent.com/acmesh-official/acme.sh/<tag>/dnsapi/dns_cf.sh \
        -o build/acme/dnsapi/dns_cf.sh
    sha256sum build/acme/acme.sh build/acme/dnsapi/dns_cf.sh
