"""Mint a CA + server leaf + client leaf for the IKEv2 EAP-TLS E2E test.

EAP-TLS is mutual-certificate auth. On the server, web/service/ikev2.go's
writeCertFiles publishes the inbound's `caCert` into charon's x509ca dir as the
CLIENT trust anchor (`ikev2-<id>-clientca.pem`), so charon validates each client
certificate against it; the same server presents its own leaf, which the CLIENT
validates against a trusted CA. The simplest arrangement (per the harness plan) is
ONE harness CA that signs BOTH leaves and is set as the inbound's `caCert`:

  - inbound.certificate/key = the server leaf (SAN = server_ip)  -> client trusts it
    via the CA it loads into its own x509ca.
  - inbound.caCert          = the CA                             -> server validates
    the client leaf against it.
  - client presents the client leaf (SAN rfc822 = client_id, signed by the same CA).

Uses the `cryptography` library, which lives in the same site-packages as the
harness's existing `requests` dependency (so it is equally available under sudo).
Returns PEM strings ready to drop into inbound settings and onto the client VM.
"""
from __future__ import annotations

import datetime
import ipaddress
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass
class Ikev2TlsCerts:
    ca_cert: str      # PEM CA: inbound.caCert (server's client-trust anchor) + the client's server-trust anchor
    server_cert: str  # PEM server leaf (SAN = server_ip): inbound.certificate
    server_key: str   # PEM server leaf key: inbound.key
    client_cert: str  # PEM client leaf (SAN rfc822 = client_id): pushed to the client VM
    client_key: str   # PEM client leaf key: pushed to the client VM
    client_id: str    # the EAP-TLS identity (rfc822 SAN on the client cert) the client sets as `local id`


def _cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


def mint(server_ip: str, client_id: str, server_id: str = "") -> Ikev2TlsCerts:
    """One self-signed CA signs a server leaf (serverAuth EKU) and a client leaf (SAN
    rfc822 = client_id, clientAuth EKU). RSA-2048 keys mirror the panel's own
    GenerateSelfSignedCert (broad IKEv2 client compatibility).

    `server_id` is the IKE identity (IDr) the server presents for this inbound. On the
    ONE shared charon, two EAP connections that present the SAME server identity can't
    be disambiguated (an EAP initiator looks identical until the method is negotiated,
    so charon picks the first EAP conn — eap-mschapv2 — and an eap-tls client rejects
    the offered MSCHAPv2). So the eap-tls inbound is given a DISTINCT server_id (a
    hostname) via settings.serverAddr; charon then selects the eap-tls conn by IDr. The
    server leaf therefore carries that hostname as a dNSName SAN so the client's
    `remote id = <server_id>` validates it. server_ip is always an iPAddress SAN too, so
    anything that keys on the IP still works. Empty server_id -> SAN = server_ip only
    (the historical single-inbound shape)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(hours=1)
    not_after = now + datetime.timedelta(days=3650)

    def _leaf(key, subject_cn, sans, eku, issuer_name, issuer_key):
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
            .issuer_name(issuer_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256())
        )

    # ---- CA (self-signed root) ----
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vpn-ui E2E IKEv2 CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    # ---- server leaf: dNSName SAN = the presented identity (server_id hostname if
    #      given, else the server_ip string) so the client's `remote id` matches; plus
    #      server_ip as an iPAddress SAN so anything keyed on the IP still works. ----
    server_name = server_id or server_ip
    server_sans = [x509.DNSName(server_name)]
    try:
        server_sans.append(x509.IPAddress(ipaddress.ip_address(server_ip)))
    except ValueError:
        pass
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_cert = _leaf(server_key, server_name or "vpn-ui", server_sans,
                        ExtendedKeyUsageOID.SERVER_AUTH, ca_name, ca_key)

    # ---- client leaf: SAN rfc822 = client_id, so the client's `local id = <client_id>`
    #      matches and charon validates the cert against the CA (== inbound.caCert). ----
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_cert = _leaf(client_key, client_id, [x509.RFC822Name(client_id)],
                        ExtendedKeyUsageOID.CLIENT_AUTH, ca_name, ca_key)

    return Ikev2TlsCerts(
        ca_cert=_cert_pem(ca_cert),
        server_cert=_cert_pem(server_cert),
        server_key=_key_pem(server_key),
        client_cert=_cert_pem(client_cert),
        client_key=_key_pem(client_key),
        client_id=client_id,
    )


if __name__ == "__main__":  # standalone smoke test: mint + verify the chain
    import sys

    certs = mint("10.6.7.42", "ik2tlsa@t")
    ca = x509.load_pem_x509_certificate(certs.ca_cert.encode())
    srv = x509.load_pem_x509_certificate(certs.server_cert.encode())
    cli = x509.load_pem_x509_certificate(certs.client_cert.encode())

    ok = True
    # Both leaves must be issued by the CA subject.
    for leaf, label in ((srv, "server"), (cli, "client")):
        if leaf.issuer != ca.subject:
            print(f"FAIL: {label} issuer {leaf.issuer.rfc4514_string()} != CA {ca.subject.rfc4514_string()}")
            ok = False
    # Server SAN must carry the IP (what the client matches `remote id` against).
    srv_ips = srv.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)
    if ipaddress.ip_address("10.6.7.42") not in srv_ips:
        print(f"FAIL: server cert missing IP SAN, has {srv_ips}")
        ok = False
    # Client SAN must carry the rfc822 identity (what it sets as `local id`).
    cli_emails = cli.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.RFC822Name)
    if "ik2tlsa@t" not in cli_emails:
        print(f"FAIL: client cert missing rfc822 SAN, has {cli_emails}")
        ok = False
    # Cryptographic signature check: each leaf really signed by the CA key.
    from cryptography.hazmat.primitives.asymmetric import padding
    for leaf, label in ((srv, "server"), (cli, "client")):
        try:
            ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                                    padding.PKCS1v15(), leaf.signature_hash_algorithm)
        except Exception as e:  # noqa: BLE001
            print(f"FAIL: {label} signature not verifiable against CA: {e}")
            ok = False

    # server_id path: a distinct hostname must land as a dNSName SAN (charon IDr match),
    # with the server IP still present as an iPAddress SAN.
    certs2 = mint("10.6.7.42", "ik2tlsa@t", server_id="ikev2-eaptls.vpn")
    srv2 = x509.load_pem_x509_certificate(certs2.server_cert.encode())
    san2 = srv2.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if "ikev2-eaptls.vpn" not in san2.get_values_for_type(x509.DNSName):
        print(f"FAIL: server_id cert missing DNS SAN, has {san2.get_values_for_type(x509.DNSName)}")
        ok = False
    if ipaddress.ip_address("10.6.7.42") not in san2.get_values_for_type(x509.IPAddress):
        print(f"FAIL: server_id cert missing IP SAN, has {san2.get_values_for_type(x509.IPAddress)}")
        ok = False

    print("PEM lengths:", len(certs.ca_cert), len(certs.server_cert), len(certs.client_cert))
    print("OK" if ok else "FAILED")
    sys.exit(0 if ok else 1)
