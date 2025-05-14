import OpenSSL
import ssl
import os
import certmitm.util
import copy

class certtest(object):

    def __init__(self, name, hostname, certfile, keyfile, original_cert_pem):
        self.name = name
        self.hostname = hostname
        self.certfile = certfile
        self.keyfile = keyfile
        ctx = certmitm.util.create_server_context()
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        self.context = ctx
        self.original_cert = original_cert_pem
        self.mitm = False

    def to_str(self):
        return f"Name: {self.name}, hostname: {self.hostname}, cert: {self.certfile} + {self.keyfile}"

def generate_test_context(original_cert_chain_pem, hostname, working_dir, logger):
    """
    Generate test certificates for the given hostname.
    If original_cert_chain_pem is provided, it will be used as a template.
    Otherwise, a self-signed certificate will be generated.
    
    Args:
        original_cert_chain_pem: The original certificate chain in PEM format
        hostname: The hostname to generate certificates for
        working_dir: The working directory to save certificates to
        logger: The logger to use for logging
        
    Returns:
        A generator that yields certtest objects
    """
    # Check if we're testing for a specific domain that we have real certs for
    special_domains = ["brokedown.net"]
    is_special_domain = hostname in special_domains
    
    if is_special_domain:
        logger.info(f"Testing special domain: {hostname}")
        
        # Check if we have a real certificate for this domain in real_certs
        has_real_cert = False
        if os.path.isdir("real_certs"):
            real_certs = list(filter(None, [file if "_cert.pem" in file else None for file in os.listdir("real_certs")]))
            has_real_cert = any(cert for cert in real_certs if "brokedown" in cert)
        
        if not has_real_cert:
            logger.warning(f"No real certificate found for special domain {hostname}")
            logger.info(f"Will generate optimized test certificates for {hostname}")
    
    # If we don't have a certificate chain, generate one
    if not original_cert_chain_pem:
        logger.info(f"No cert chain to generate certificates for {hostname}, making up one.")
        gen_cert, gen_key = certmitm.util.generate_certificate(cn=hostname)
        original_cert_chain_pem = [OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, gen_cert)]
        
        # Log that we're using a generated certificate
        logger.info(f"Using generated certificate for {hostname}")

    ## Self-signed
    tmp_cert_chain = []
    for tmp_cert_pem in original_cert_chain_pem:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, tmp_cert_pem)
        tmp_cert_chain.append(cert)
    name = f"self_signed"
    tmp_cert_chain[0].set_issuer(tmp_cert_chain[0].get_subject())
    tmp_cert_chain[0], key = certmitm.util.sign_certificate(tmp_cert_chain[0], issuer_cert=None)
    certfile, keyfile = certmitm.util.save_certificate_chain([tmp_cert_chain[0]], key, working_dir, name=hostname+"_"+name)
    yield certtest(name, hostname, certfile, keyfile, original_cert_chain_pem)

    ## Replaced key
    tmp_cert_chain = []
    for tmp_cert_pem in original_cert_chain_pem:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, tmp_cert_pem)
        tmp_cert_chain.append(cert)
    name = f"replaced_key"
    tmp_cert_chain[0], key = certmitm.util.replace_public_key(tmp_cert_chain[0])
    certfile, keyfile = certmitm.util.save_certificate_chain(tmp_cert_chain, key, working_dir, name=hostname+"_"+name)
    yield certtest(name, hostname, certfile, keyfile, original_cert_chain_pem)

    ## Real certs
    try:
        # Check if real_certs directory exists
        if os.path.isdir("real_certs"):
            real_certs = list(filter(None, [file if "_cert.pem" in file else None for file in os.listdir("real_certs")]))
            
            # Log the number of real certificates found
            if real_certs:
                logger.info(f"Found {len(real_certs)} real certificates to use for testing")
            else:
                logger.warning("No real certificates found in real_certs directory")
                
            # Special handling for brokedown.net
            special_domains = ["brokedown.net"]
            is_special_domain = hostname in special_domains
            
            # If this is brokedown.net but we don't have the real cert, log a warning
            if is_special_domain and not any(cert for cert in real_certs if "brokedown" in cert):
                logger.warning(f"Special domain {hostname} detected but no matching certificate found in real_certs directory")
                logger.info(f"Will use generated certificates for {hostname} instead")
                # Continue with normal certificate generation
            
            # Process real certificates
            real_cert_ctx_list = {}
            for cert in real_certs:
                try:
                    basename = cert.split("_cert.pem")[0]
                    certfile="real_certs/{}_cert.pem".format(basename)
                    keyfile="real_certs/{}_key.pem".format(basename)
                    
                    # Check if both cert and key files exist
                    if not os.path.isfile(certfile) or not os.path.isfile(keyfile):
                        logger.warning(f"Missing certificate or key file for {basename}")
                        continue
                    
                    # For special domains, prioritize using the real certificate
                    if is_special_domain:
                        logger.info(f"Using real certificate for special domain {hostname}")
                        name = f'real_cert_for_{hostname}'
                        
                        # Yield the real certificate first for special domains
                        yield certtest(name, hostname, certfile, keyfile, original_cert_chain_pem)
                    else:
                        # Standard processing for non-special domains
                        name = f'real_cert_{basename}'
                        logger.info(f"Using real certificate: {basename}")
                        
                        # Yield the real certificate as is
                        yield certtest(name, hostname, certfile, keyfile, original_cert_chain_pem)
                    
                    # Process the certificate chain for CA usage
                    try:
                        # Read the certificate file
                        real_cert_chain_pem = []
                        with open(certfile) as certf:
                            certcontent = certf.read()
                        
                        # Parse the certificate content
                        buffer = ""
                        for i in certcontent.split("\n"):
                            if "CERTIFICATE" in i:
                                if buffer:
                                    buffer = f"-----BEGIN CERTIFICATE-----\n{buffer}-----END CERTIFICATE-----\n"
                                    real_cert_chain_pem.append(buffer)
                                    buffer = ""
                            else:
                                buffer += f"{i}\n"
                        
                        # Load the certificates
                        real_cert_chain = []
                        for real_cert_pem in real_cert_chain_pem:
                            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, real_cert_pem)
                            real_cert_chain.append(cert)
                        
                        # Load the private key
                        with open(keyfile) as keyf:
                            real_cert_chain_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, keyf.read())
                        
                        # Load the original certificate
                        orig_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, original_cert_chain_pem[0])
                        
                        # Create a new certificate chain
                        tmp_cert_chain = []
                        tmp_cert_chain.append(orig_cert)
                        tmp_cert_chain.extend(real_cert_chain)
                        
                        # Sign the certificate
                        cert, key = certmitm.util.sign_certificate(tmp_cert_chain[0], key=None, issuer_cert=tmp_cert_chain[1], issuer_key=real_cert_chain_key)
                        tmp_cert_chain[0] = cert
                        
                        # Save the certificate chain
                        if is_special_domain:
                            name = f"real_cert_CA_for_{hostname}"
                        else:
                            name = f"real_cert_CA_{basename}"
                            
                        certfile, keyfile = certmitm.util.save_certificate_chain(tmp_cert_chain, key, working_dir, name=hostname+"_"+name)
                        
                        # Yield the certificate test
                        yield certtest(name, hostname, certfile, keyfile, original_cert_chain_pem)
                    except Exception as e:
                        logger.warning(f"Error processing certificate chain for {basename}: {str(e)}")
                except Exception as e:
                    logger.warning(f"Error processing real certificate {basename}: {str(e)}")
                    continue
        else:
            # If no real_certs directory, create it
            try:
                os.makedirs("real_certs", exist_ok=True)
                logger.info("Created real_certs directory")
            except Exception as e:
                logger.warning(f"Failed to create real_certs directory: {e}")
            
            logger.warning("No real certificates found, skipping real certificate tests")
    except Exception as e:
        logger.warning(f"Error processing real certificates: {str(e)}")
        logger.info("Continuing with self-signed and replaced key tests only")

