import os
import subprocess
from flask import Flask, render_template, request, send_file

app = Flask(__name__)

# Paths to your Root CA and Key (update these as per your setup)
CA_CERT = "/etc/ca/root-ca.pem"
CA_KEY = "/etc/ca/root-ca.key"
UPLOAD_FOLDER = "uploads"
SIGNED_CERTS_FOLDER = "signed_certs"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(SIGNED_CERTS_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_csr():
    if 'csr' not in request.files or 'config' not in request.files:
        return "Missing CSR or config file", 400

    csr_file = request.files['csr']
    config_file = request.files['config']

    if csr_file.filename == '' or config_file.filename == '':
        return "No selected file", 400

    # Save CSR and req.conf
    csr_filename = csr_file.filename.rsplit('.', 1)[0]  # Remove extension
    csr_path = os.path.join(UPLOAD_FOLDER, csr_file.filename)
    config_path = os.path.join(UPLOAD_FOLDER, config_file.filename)
    signed_cert_path = os.path.join(SIGNED_CERTS_FOLDER, csr_filename + ".crt")

    csr_file.save(csr_path)
    config_file.save(config_path)

    # Sign CSR with provided req.conf
    openssl_cmd = [
        "openssl", "x509", "-req",
        "-in", csr_path,
        "-CA", CA_CERT,
        "-CAkey", CA_KEY,
        "-CAcreateserial",
        "-out", signed_cert_path,
        "-days", "365",
        "-sha256",
        "-extfile", config_path
    ]

    try:
        subprocess.run(openssl_cmd, check=True)
    except subprocess.CalledProcessError as e:
        return f"Error signing CSR: {str(e)}", 500

    os.remove(csr_path)  # Remove CSR after signing
    os.remove(config_path)  # Remove config after signing

    return send_file(signed_cert_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
