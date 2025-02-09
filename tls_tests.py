import unittest
import subprocess
import os
import tempfile

class TestCertificateGeneration(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.cert_path = os.path.join(self.test_dir.name, "server_cert.pem")
        self.key_path = os.path.join(self.test_dir.name, "server_key.pem")
        self.root_cert_path = os.path.join(self.test_dir.name, "root_cert.pem")

    def tearDown(self):
        self.test_dir.cleanup()

    def test_generate_certificate_with_san(self):
        cmd = [
            "python3", "main.py",
            "--country", "US",
            "--province", "MD",
            "--locality", "ROCKVILLE",
            "--organization", "TestOrg",
            "--common_name", "localhost",
            "--ca_name", "TestCA",
            "--subject_alt_names", "localhost 127.0.0.1 192.168.1.100",
            "--output_dir", self.test_dir.name
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"Error: {result.stderr}")

        self.assertTrue(os.path.exists(self.cert_path), "Server certificate not generated")
        
        san_output = subprocess.run(
            ["openssl", "x509", "-in", self.cert_path, "-text", "-noout"],
            capture_output=True, text=True
        ).stdout

        self.assertIn("DNS:localhost", san_output, "Missing hostname in SANs")
        self.assertIn("IP Address:127.0.0.1", san_output, "Missing 127.0.0.1 in SANs")
        self.assertIn("IP Address:192.168.1.100", san_output, "Missing 192.168.1.100 in SANs")

    def test_certificate_contains_only_localhost(self):
        """Ensure that the certificate has 'localhost' as the CN and only 'localhost' in SANs."""
        
        # Generate certificate with only 'localhost'
        cmd = [
            "python3", "main.py",
            "--country", "US",
            "--province", "MD",
            "--locality", "ROCKVILLE",
            "--organization", "TestOrg",
            "--common_name", "localhost",
            "--ca_name", "TestCA",
            "--output_dir", self.test_dir.name  # Save certs in temp directory
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, msg=f"Certificate generation failed: {result.stderr}")

        cert_output = subprocess.run(
            ["openssl", "x509", "-in", self.cert_path, "-text", "-noout"],
            capture_output=True, text=True
        ).stdout
        print(cert_output)
        self.assertIn("CN=localhost", cert_output, "Common Name (CN) is not localhost")

        self.assertIn("DNS:localhost", cert_output, "SANs do not contain 'localhost'")
        self.assertNotIn("IP Address:", cert_output, "Unexpected IP Address found in SANs")
        self.assertNotIn("DNS:", cert_output.replace("DNS:localhost", ""), "Unexpected DNS names found in SANs")

if __name__ == "__main__":
    unittest.main()

