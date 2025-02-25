from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import os
import ipaddress
from dataclasses import dataclass
import argparse

@dataclass
class CertInfo:
    country: str
    province: str
    locality: str
    organization: str
    common_name: str
    ca_name: str
    subject_alt_names: list = None 

    def __str__(self):
        return (
            f"Certificate Information:\n"
            f"  Country: {self.country}\n"
            f"  Province: {self.province}\n"
            f"  Locality: {self.locality}\n"
            f"  Organization: {self.organization}\n"
            f"  Common Name: {self.common_name}\n"
            f"  Certificate Authority: {self.ca_name}\n"
            f"  Subject Alt Names: {self.subject_alt_names}")

def _generate_private_key():
    """
    Generates a private RSA key.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return key

def _generate_root_certificate(*, root_key, cert_info):
    """
    Generates a self-signed root certificate using the provided private key.
    Returns the certificate object and its serialized PEM format.
    """

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, cert_info.country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, cert_info.province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, cert_info.locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, cert_info.organization),
        x509.NameAttribute(NameOID.COMMON_NAME, cert_info.ca_name),
    ])

    root_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        root_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(root_key, hashes.SHA256(), default_backend())

    return root_cert, root_cert.public_bytes(serialization.Encoding.PEM)

def _generate_server_certificate(*, server_key, root_cert_obj, root_key, cert_info):
    """
    Generates a server certificate signed by the provided root certificate.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, cert_info.country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, cert_info.province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, cert_info.locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, cert_info.organization),
        x509.NameAttribute(NameOID.COMMON_NAME, cert_info.common_name),
    ])


    san_list = []
    if cert_info.subject_alt_names:
        for name in cert_info.subject_alt_names:
            try:
                san_list.append(x509.IPAddress(ipaddress.IPv4Address(name)))
            except ipaddress.AddressValueError:
                san_list.append(x509.DNSName(name))
    else:
        try:
            san_list.append(x509.IPAddress(ipaddress.IPv4Address(cert_info.common_name)))
        except ipaddress.AddressValueError:
            san_list.append(x509.DNSName(cert_info.common_name))

    san = x509.SubjectAlternativeName(san_list)
    
    server_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert_obj.subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).add_extension( san,
        critical=False,).sign(root_key, hashes.SHA256(), default_backend())

    return server_cert.public_bytes(serialization.Encoding.PEM)

def _save_to_file(data, filename):
    """
    Saves the given data to a file.
    """

    with open(filename, 'wb') as f:
        f.write(data)

def _main(cert_info, output_dir="./certs"):

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Generate root key and self-signed root certificate
    root_key = _generate_private_key()
    root_cert_obj, root_cert_pem = _generate_root_certificate(root_key=root_key,
                                                              cert_info=cert_info)

    # Generate server key
    server_key = _generate_private_key()

    # Generate server certificate signed by the root certificate
    server_cert = _generate_server_certificate(server_key=server_key,
                                               root_cert_obj=root_cert_obj,
                                               root_key=root_key,
                                               cert_info=cert_info)

    # Convert keys to PEM format for saving
    root_key_pem = root_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    server_key_pem = server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    _save_to_file(root_key_pem, os.path.join(output_dir, "root_key.pem"))
    _save_to_file(root_cert_pem, os.path.join(output_dir, "root_cert.pem"))
    _save_to_file(server_key_pem, os.path.join(output_dir, "server_key.pem"))
    _save_to_file(server_cert, os.path.join(output_dir, "server_cert.pem"))

def _parse_args():
    parser = argparse.ArgumentParser(description="Generate TLS Certificates")
    parser.add_argument("--country", required=True, help="Country code")
    parser.add_argument("--province", required=True, help="Province or state")
    parser.add_argument("--locality", required=True, help="Locality or city")
    parser.add_argument("--organization", required=True, help="Organization name")
    parser.add_argument("--common_name", required=True, help="Common name (domain)")
    parser.add_argument("--ca_name", required=True, help="Name to use as the CA in the root certificate")
    parser.add_argument("--subject_alt_names", default=None, help="Space-separated list of SANs (IPs/DNS names, optional)")
    parser.add_argument("--output_dir", default="./certs", help="Directory to save generated certificates")
    return parser.parse_args()

if __name__ == "__main__":
    args = _parse_args()
    
    subject_alt_names = args.subject_alt_names.split() if args.subject_alt_names else []
    if args.common_name not in subject_alt_names:
        subject_alt_names.append(args.common_name)

    cert_info = CertInfo(
        country=args.country,
        province=args.province,
        locality=args.locality,
        organization=args.organization,
        common_name=args.common_name,
        ca_name=args.ca_name,
        subject_alt_names=subject_alt_names
    )

    _main(cert_info, args.output_dir)

