import OpenSSL
import ssl
import socket
import struct
import os
import subprocess
import logging
import dpkt
import random
from cryptography.hazmat.primitives import serialization

def SNIFromHello(data):
    TLS_HANDSHAKE = 22
    if not data or data[0] != TLS_HANDSHAKE:
        return None
    records = []
    try:
        records, bytes_used = dpkt.ssl.tls_multi_factory(data)
    except dpkt.ssl.SSL3Exception:
        # dpkt does not support SSL3 for some reason
        return None
    for record in records:
        # TLS handshake only
        if record.type != 22:
            continue
        if len(record.data) == 0:
            continue
        # Client Hello only
        if record.data[0] != 1:
            continue

        handshake = dpkt.ssl.TLSHandshake(record.data)

        if not isinstance(handshake.data, dpkt.ssl.TLSClientHello):
            continue
        
        ch = handshake.data
        for ext in ch.extensions:
            SNI_EXTENSION = 0
            if ext[0] == SNI_EXTENSION:
                sni_ext = ext[1]
                sni_ext_len = int.from_bytes(sni_ext[:2], 'big')
                sni_len = int.from_bytes(sni_ext[3:5], 'big')
                if sni_len + 3 != sni_ext_len:
                    # There are multiple SNIs in one client hello
                    raise NotImplementedError
                sni = str(sni_ext[5:5+sni_len], 'utf-8')
                return sni
    return None

def createLogger(name):
    logger = logging.getLogger(name)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(LogColorFormatter())
    logger.addHandler(ch)
    return logger

class LogColorFormatter(logging.Formatter):
    grey = "\x1b[38;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    format = "%(levelname)s - %(message)s"
    FORMATS = {
        logging.DEBUG: grey + format + reset,
        logging.INFO: grey + format + reset,
        logging.WARNING: yellow + format + reset,
        logging.ERROR: red + format + reset,
        logging.CRITICAL: bold_red + format + reset
    }
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def create_client_context():
    upstream_context = ssl.create_default_context()
    upstream_context.set_ciphers('ALL')
    upstream_context.check_hostname = False
    upstream_context.verify_mode = ssl.CERT_NONE
    upstream_context.verify = False
    return upstream_context

def create_server_context():
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.set_ciphers('ALL')
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    return ctx

# Deletes a specific extension from a cert
def delete_extension(cert, extension):
    new_cert = OpenSSL.crypto.X509()
    new_cert.set_issuer(cert.get_issuer())
    new_cert.set_notAfter(cert.get_notAfter())
    new_cert.set_notBefore(cert.get_notBefore())
    new_cert.set_serial_number(cert.get_serial_number())
    new_cert.set_subject(cert.get_subject())
    new_cert.set_version(cert.get_version())
    new_cert.set_pubkey(cert.get_pubkey())
    new_extensions = []
    for i in range(cert.get_extension_count()):
        original_extension = cert.get_extension(i)
        if not original_extension.get_short_name() == extension:
            new_extensions.append(original_extension)
    new_cert.add_extensions(new_extensions)
    return new_cert

# Saves a certificate/key pair and returns the filenames for them
def save_certificate_chain(certs, key, working_dir, name=None):
    if not name:
        name = str(cert.get_subject().commonName)
    directory = os.path.join(working_dir, "certificates")
    if not os.path.isdir(directory):
        os.mkdir(directory)
    for postfix in "_cert", "_key":
        for filetype in ".pem", ".der", ".crt":
            filename = os.path.join(directory,name+postfix+filetype)
            with open(filename,"wb") as f:
                if ".pem" in filetype:
                    filetype = OpenSSL.crypto.FILETYPE_PEM
                    if "_cert" in postfix:
                        pem_cert = filename
                    else:
                        pem_key = filename
                else:
                    filetype = OpenSSL.crypto.FILETYPE_ASN1
                if "_cert" in postfix:
                    for cert in certs:
                        f.write(OpenSSL.crypto.dump_certificate(filetype, cert))
                else:
                    f.write(OpenSSL.crypto.dump_privatekey(filetype, key))
    return pem_cert, pem_key

# Signs a certificate and returns it and its key
def sign_certificate(cert, key=None, issuer_cert=None, issuer_key=None, keytype="RSA", keysize=2048):
    if not key:
        # Generate RSA/DSA key (Default RSA with 2048 bits)
        key = OpenSSL.crypto.PKey()
        if keytype == "RSA":
            key.generate_key(OpenSSL.crypto.TYPE_RSA,keysize)
        elif keytype == "DSA":
            key.generate_key(OpenSSL.crypto.TYPE_DSA,keysize)
        else:
            logging.critical("Invalid key type! Key type must be RSA/DSA.")
            exit()

    # Set certificate issuer and public key
    if issuer_cert is not None:
        cert.set_issuer(issuer_cert.get_subject())
    else:
        cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)

    # Sign certificate
    if issuer_key is None:
        cert.sign(key,'sha256')
    else:
        cert.sign(issuer_key,'sha256')
    return cert, key

# Generates a matching keypair for the certificate and replaces the original key
def replace_public_key(cert, key=None, keytype=None, keysize=None):
    if key or keytype or keysize:
        raise NotImplementedError
        # Generate RSA/DSA key (Default RSA with 2048 bits)
        #key = OpenSSL.crypto.PKey()
        #if keytype == "RSA":
        #    key.generate_key(OpenSSL.crypto.TYPE_RSA,keysize)
        #elif keytype == "DSA":
        #    key.generate_key(OpenSSL.crypto.TYPE_DSA,keysize)
        #else:
        #    print("Invalid key type! Key type must be RSA/DSA.")
        #    exit()
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA,2048)
    cert.set_pubkey(key)

    # Sign certificate
    cert.sign(key,'sha256')
    return cert, key

def generate_certificate(version=2, id=None, c=None, st=None, l=None, o=None, cn="certmitm", ca="FALSE", before=-(365*24*60*60), after=(365*24*60*60), keytype="RSA", keysize=2048, name=None, failmessage=None, successmessage=None, valid=None, issuer_cert=None, issuer_key=None, exception=None, dest=None):
    if not id:
        id = random.randint(10000000000000000000,99999999999999999999)

    # Create X509 certificate object
    cert = OpenSSL.crypto.X509()
    # Set version and serial number
    cert.set_version(version)
    cert.set_serial_number(id)

    # set certificate subject fields
    subj = cert.get_subject()
    if c:
        subj.countryName = c
    if st:
        subj.stateOrProvinceName = st
    if l:
        subj.localityName = l
    if o:
        subj.organizationName = o
    if cn:
        subj.commonName = cn[:60]

    # add certificate extensions
    if ca == "TRUE":
        cert.add_extensions([
            OpenSSL.crypto.X509Extension(b"basicConstraints","critical",bytes("CA:TRUE","utf-8")),
    #        OpenSSL.crypto.X509Extension(b"keyUsage",False,b"keyCertSign, cRLSign")
        ])
    else:
        cert.add_extensions([
            OpenSSL.crypto.X509Extension(b"basicConstraints","critical",bytes("CA:FALSE","utf-8")),
    #        OpenSSL.crypto.X509Extension(b"keyUsage","critical",b"digitalSignature, keyEncipherment")
        ])
        if cn:
            cert.add_extensions([
                OpenSSL.crypto.X509Extension(b"subjectAltName", False, b"DNS:" + bytes(cn, 'utf-8'))
            ])

    #cert.add_extensions([
    #    OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert)
    #])

    #cert.add_extensions([
    #    OpenSSL.crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=cert)
    #])

    # set validity time
    cert.gmtime_adj_notBefore(before)
    cert.gmtime_adj_notAfter(after)

    cert, key = sign_certificate(cert, key=None, issuer_cert=issuer_cert, issuer_key=issuer_key, keytype=keytype, keysize=keysize)

    # Return certificate and key
    return cert, key

# Get the original destination of the intercepted socket.
def sock_to_dest(sock):
    dst = (sock.getsockopt(socket.SOL_IP, 80, 16))
    port, raw_ip = struct.unpack_from("!2xH4s", dst)
    ip = socket.inet_ntop(socket.AF_INET, raw_ip)
    return  ip, port

# Try to get server certificate with OpenSSL
def get_cert_chain(dest_ip, dest_port, req_hostname):
    context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
    client = socket.socket()
    client.settimeout(5)  # Set a 5-second timeout for the connection
    try:
        client.connect((dest_ip, dest_port))
        clientSSL = OpenSSL.SSL.Connection(context, client)
        if req_hostname:
            clientSSL.set_tlsext_host_name(bytes(req_hostname, 'utf-8'))
        clientSSL.set_verify(OpenSSL.SSL.VERIFY_NONE)
        clientSSL.set_connect_state()
        clientSSL.do_handshake()
        return clientSSL.get_peer_cert_chain()
    except socket.timeout:
        raise TimeoutError("Connection to server timed out")
    finally:
        client.close()

# Try to get server certificate with openssl s_client
# Needed as get_peer_cert_chain fails if the server wants a client certificate
def get_cert_chain_sclient(dest_ip, dest_port, req_hostname):
    try:
        # Add a timeout to the subprocess call
        s_client = subprocess.run(
            ["openssl", "s_client", "-host", str(dest_ip), "-port", str(dest_port), 
             "-servername", str(req_hostname), "-showcerts", "-connect_timeout", "5"],
            input="", stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10
        )
        
        cert_fullchain = []
        for i in s_client.stdout.split(b"-----BEGIN CERTIFICATE-----")[1:]:
            cert_string = i.split(b"-----END CERTIFICATE-----")[0]
            cert_string = f"-----BEGIN CERTIFICATE-----{cert_string.decode('utf-8')}-----END CERTIFICATE-----"
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_string)
            cert_fullchain.append(cert)
        return cert_fullchain
    except subprocess.TimeoutExpired:
        raise TimeoutError("OpenSSL s_client command timed out")

def get_server_cert_fullchain(dest_ip, dest_port, req_hostname):
    fullchain = []
    # Create a logger for this function
    logger = logging.getLogger("log")
    
    logger.debug(f"Attempting to get certificate chain for {dest_ip}:{dest_port} (SNI: {req_hostname})")
    
    try:
        logger.debug("Trying direct OpenSSL connection...")
        certificate_chain = get_cert_chain(dest_ip, dest_port, req_hostname)
        logger.debug("Successfully retrieved certificate chain via direct OpenSSL")
    except (OpenSSL.SSL.Error, OSError, ConnectionRefusedError, TimeoutError) as e:
        logger.debug(f"Direct OpenSSL connection failed: {str(e)}")
        try:
            logger.debug("Trying openssl s_client command...")
            certificate_chain = get_cert_chain_sclient(dest_ip, dest_port, req_hostname)
            logger.debug("Successfully retrieved certificate chain via openssl s_client")
        except (OSError, ConnectionRefusedError, TimeoutError) as e:
            logger.debug(f"openssl s_client command failed: {str(e)}")
            logger.warning(f"Failed to retrieve certificate chain for {dest_ip}:{dest_port} (SNI: {req_hostname})")
            certificate_chain = None
    
    if certificate_chain:
        for cert in certificate_chain:
            pem_file = cert.to_cryptography().public_bytes(serialization.Encoding.PEM)
            fullchain.append(pem_file)
        logger.debug(f"Returning certificate chain with {len(fullchain)} certificates")
        return fullchain
    
    # If we can't get a certificate, generate a fake one to allow testing to continue
    logger.debug("No certificate chain found, generating a self-signed certificate")
    return None

