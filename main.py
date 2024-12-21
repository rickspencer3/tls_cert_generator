from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import os
import ipaddress

def generate_private_key():
    """
    Generates a private RSA key.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return key

def generate_root_certificate(root_key):
    """
    Generates a self-signed root certificate using the provided private key.
    Returns the certificate object and its serialized PEM format.
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MD"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Rockville"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"self"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"self-signed-root"),
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
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(root_key, hashes.SHA256(), default_backend())

    return root_cert, root_cert.public_bytes(serialization.Encoding.PEM)

def generate_server_certificate(server_key, root_cert_obj, root_key):
    """
    Generates a server certificate signed by the provided root certificate.
    """
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MD"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Rockville"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"self"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"127.0.0.1"),
    ])

    server_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert_obj.subject
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).add_extension(
    x509.SubjectAlternativeName([
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
    ]),
    critical=False,).sign(root_key, hashes.SHA256(), default_backend())

    return server_cert.public_bytes(serialization.Encoding.PEM)

def save_to_file(data, filename):
    """
    Saves the given data to a file.
    """
    print(filename)
    with open(filename, 'wb') as f:
        f.write(data)

def main(certs_dir="./certs"):
    """
    Generates a server key, server certificate signed by the root certificate,
    root key, and root certificate. Saves them in the specified directory.
    """
    if not os.path.exists(certs_dir):
        os.makedirs(certs_dir)

    # Generate root key and self-signed root certificate
    root_key = generate_private_key()
    root_cert_obj, root_cert_pem = generate_root_certificate(root_key)

    # Generate server key
    server_key = generate_private_key()

    # Generate server certificate signed by the root certificate
    server_cert = generate_server_certificate(server_key, root_cert_obj, root_key)

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

    # Save files
    save_to_file(root_key_pem, os.path.join(certs_dir, "root_key.pem"))
    save_to_file(root_cert_pem, os.path.join(certs_dir, "root_cert.pem"))
    save_to_file(server_key_pem, os.path.join(certs_dir, "server_key.pem"))
    save_to_file(server_cert, os.path.join(certs_dir, "server_cert.pem"))

if __name__ == "__main__":
    main()
