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

if __name__ == "__main__":
    unittest.main()

