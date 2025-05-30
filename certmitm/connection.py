import certmitm.util
import certmitm.certtest
import socket
import threading
import time
import os
import json
import ssl

def counter():
    i = 0
    while True:
        yield i
        i += 1

connection_counter = counter()

class connection(object):

    def __init__(self, client_socket, logger, listen_port=9900):
        self.id = next(connection_counter)
        self.timestamp = time.time()
        self.lock = threading.Lock()
        self.logger = logger
        self.client_socket = client_socket
        self.listen_port = listen_port
        
        # Get client information
        self.client_name = str(client_socket.getpeername())
        self.client_ip = self.client_name.split("'")[1]
        self.client_port = int(self.client_name.split(" ")[1].split(')')[0]) #Dirty I know :)
        
        # Get original destination
        self.upstream_ip, self.upstream_port = certmitm.util.sock_to_dest(self.client_socket)
        
        # Check for connection loops - detect if we're trying to connect to ourselves
        self.is_loop = False
        
        # Check if connecting to our own listen port on any interface
        if self.upstream_port == self.listen_port:
            # Check if connecting to localhost
            if self.upstream_ip == "127.0.0.1" or self.upstream_ip == "::1":
                self.logger.warning(f"Detected connection loop to localhost:{self.upstream_port}")
                self.is_loop = True
                # Redirect to a different port for testing
                self.upstream_port = 10000
            
            # Check if connecting to our own IP
            else:
                # Get our own IP addresses
                own_ips = certmitm.util.get_own_ip_addresses()
                if self.upstream_ip in own_ips:
                    self.logger.warning(f"Detected connection loop to {self.upstream_ip}:{self.upstream_port}")
                    self.is_loop = True
                    # Redirect to a different port for testing
                    self.upstream_port = 10000
        
        # Try to get SNI from client hello
        try:
            self.upstream_sni = certmitm.util.SNIFromHello(self.client_socket.recv(4096, socket.MSG_PEEK))
        except (TimeoutError, ConnectionResetError):
            self.upstream_sni = None
            
        # Set upstream name based on SNI or IP
        if self.upstream_sni:
            self.upstream_name = self.upstream_sni
        else:
            self.upstream_name = self.upstream_ip
            
        self.upstream_str = f"{self.upstream_ip}:{self.upstream_port}:{self.upstream_sni}"
        self.identifier = str([self.client_ip, self.upstream_name, self.upstream_port])

    def to_str(self):
        return f"ID: {self.id}, Client: {self.client_ip}:{self.client_port}, Upstream: {self.upstream_ip}:{self.upstream_port} '{self.upstream_sni}', Identifier: {self.identifier}"

class connection_tests(object):

    def __init__(self, logger, working_dir, retrytests, skiptests):
        self.all_test_dict = {}
        self.current_test_dict = {}
        self.lock = threading.Lock()
        self.logger = logger
        self.working_dir = working_dir
        self.retrytests = retrytests
        self.skiptests = skiptests

    def log(self, connection, who, what):
        self.all_test_dict[connection.identifier].log(connection.timestamp, who, what)

    def get_test(self, connection):
        # If the connection is first of its kind
        if connection.identifier not in self.all_test_dict.keys():
            with self.lock:
                if connection.identifier not in self.all_test_dict.keys():
                    # Create a dict to store tests for the connection identifier 
                    self.all_test_dict[connection.identifier] = certmitm.connection.test_list(connection, self.logger, self.working_dir, self.retrytests, self.skiptests)
                    self.logger.debug(f"Created a test dict: '{self.all_test_dict[connection.identifier].to_str()}'")


        # Get next test based on the connection identifier
        next_test = self.all_test_dict[connection.identifier].get_test()
        if next_test:
            self.current_test_dict[connection.client_name] = next_test
            return next_test

        return None

    def add_successfull_test(self, connection, test):
        self.all_test_dict[connection.identifier].add_successfull_test(test)
        self.logger.debug(f"Succesfull test list now: {self.all_test_dict[connection.identifier].successfull_test_list}")

class test_list(object):

    def __init__(self, connection, logger, working_dir, retrytests, skiptests):
        self.connection = connection
        self.lock = threading.Lock()
        self.test_list = None
        self.successfull_test_list = []
        self.logger = logger
        self.working_dir = working_dir
        self.retrytests = retrytests
        self.skiptests = skiptests
        self.errorpath = os.path.join(self.working_dir,self.connection.client_ip)
        self.mitmdatadir = os.path.join(self.errorpath,self.connection.upstream_name,"data")
        self.certpath = os.path.join(self.errorpath,self.connection.upstream_name,"certs")

    def log(self, timestamp, who, what):
        # Special handling for HTTP info logs (which are JSON strings)
        if who.endswith('_http_info') and isinstance(what, str):
            # Create HTTP info log file
            httpinfofilename = os.path.join(self.mitmdatadir, f'{timestamp}.httpinfo.json')
            dirname = os.path.dirname(httpinfofilename)
            
            if not os.path.exists(dirname):
                os.makedirs(dirname)
                
            # Write HTTP info as JSON
            with open(httpinfofilename, 'a') as httpinfofile:
                httpinfofile.write(f"{what}\n")
            return
            
        # Regular binary data logging
        txtfilename = os.path.join(self.mitmdatadir, f'{timestamp}.txt')
        binfilename = os.path.join(self.mitmdatadir, f'{timestamp}.bin')
        hexfilename = os.path.join(self.mitmdatadir, f'{timestamp}.hex')
        httpfilename = os.path.join(self.mitmdatadir, f'{timestamp}.http')
        dirname = os.path.dirname(txtfilename)
        
        if not os.path.exists(dirname):
            os.makedirs(dirname)
            
        # Write binary data as-is to binary file
        with open(binfilename, 'ab') as binmitmfile:
            binmitmfile.write(what)
        
        # Create a better text representation for the text log
        try:
            # Try to decode as UTF-8 if possible
            data_str = what.decode('utf-8', errors='replace')
            # Clean up control characters for better display
            data_str = ''.join(c if c.isprintable() or c in '\n\r\t' else f'\\x{ord(c):02x}' for c in data_str)
        except:
            # If decoding fails, use a placeholder
            data_str = f"[Binary data, {len(what)} bytes]"
        
        # Write JSON log with proper metadata
        with open(txtfilename, 'a') as txtmitmfile:
            log_entry = {
                "timestamp": str(time.time()),
                "from": str(who),
                "size": len(what),
                "data": data_str
            }
            jsondata = json.dumps(log_entry)
            txtmitmfile.write(f'{jsondata}\n')
        
        # Write hex dump for binary analysis
        with open(hexfilename, 'a') as hexmitmfile:
            hexmitmfile.write(f"--- {who} at {time.time()} ({len(what)} bytes) ---\n")
            
            # Create a hex dump with both hex and ASCII representation
            offset = 0
            while offset < len(what):
                # Get 16 bytes for this line
                chunk = what[offset:offset+16]
                
                # Format as hex
                hex_line = ' '.join(f'{b:02x}' for b in chunk)
                hex_line = hex_line.ljust(49)  # Pad to consistent width
                
                # Format as ASCII (printable chars only)
                ascii_line = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                
                # Write the line with offset
                hexmitmfile.write(f"{offset:08x}:  {hex_line}  |{ascii_line}|\n")
                offset += 16
            
            hexmitmfile.write("\n")
            
        # Try to parse and format HTTP data if this might be HTTP
        try:
            # Check if this looks like HTTP data
            if (what.startswith(b'HTTP/') or 
                what.startswith(b'GET ') or 
                what.startswith(b'POST ') or 
                what.startswith(b'PUT ') or 
                what.startswith(b'DELETE ')):
                
                # Format HTTP data for better readability
                with open(httpfilename, 'a') as httpfile:
                    httpfile.write(f"--- {who} at {time.time()} ({len(what)} bytes) ---\n")
                    
                    # Try to split headers and body
                    if b'\r\n\r\n' in what:
                        headers, body = what.split(b'\r\n\r\n', 1)
                        
                        # Write headers with line breaks
                        header_lines = headers.split(b'\r\n')
                        for line in header_lines:
                            httpfile.write(f"{line.decode('utf-8', errors='replace')}\n")
                        
                        httpfile.write("\n")  # Empty line between headers and body
                        
                        # Try to decode body as text if possible
                        try:
                            body_str = body.decode('utf-8', errors='replace')
                            httpfile.write(body_str)
                        except:
                            httpfile.write(f"[Binary body data, {len(body)} bytes]")
                    else:
                        # Just write the whole thing if we can't split it
                        httpfile.write(what.decode('utf-8', errors='replace'))
                    
                    httpfile.write("\n\n")
        except Exception as e:
            # If HTTP parsing fails, just continue
            pass

    def get_test(self):
        # If the tests have not yet been generated
        if self.test_list == None:
            with self.lock:
                if not self.test_list:
                    # Get upstream fullchain from the server
                    self.logger.debug(f"New connection to {self.connection.upstream_str}")
                    try:
                        # Log that we're attempting to get the certificate chain
                        self.logger.info(f"Retrieving certificate chain for {self.connection.upstream_str}")
                        
                        # Get the certificate chain
                        self.upstream_cert_fullchain = certmitm.util.get_server_cert_fullchain(self.connection.upstream_ip, self.connection.upstream_port, self.connection.upstream_sni)
                        
                        # Log success or failure
                        if self.upstream_cert_fullchain:
                            self.logger.info(f"Successfully retrieved certificate chain with {len(self.upstream_cert_fullchain)} certificates")
                            self.logger.debug(f"{self.connection.upstream_str} fullchain: '{self.upstream_cert_fullchain}'")
                        else:
                            self.logger.warning(f"No certificate chain retrieved for {self.connection.upstream_str}")
                            self.upstream_cert_fullchain = None
                    except Exception as e:
                        self.logger.warning(f"Error getting certificate chain: {str(e)}")
                        self.logger.info("Will continue with self-signed certificate")
                        self.upstream_cert_fullchain = None
                        
                    # Initialize test list
                    self.test_list = []
                    
                    # Generate list of tests for the connection
                    # Even if we couldn't get a certificate chain, we'll generate tests with a self-signed cert
                    try:
                        self.logger.info(f"Generating certificate tests for {self.connection.upstream_str}")
                        
                        # Track how many tests we generate
                        test_count = 0
                        
                        # Generate the tests
                        for test in certmitm.certtest.generate_test_context(self.upstream_cert_fullchain, self.connection.upstream_sni or self.connection.upstream_ip, self.working_dir, self.logger):
                            for i in range(int(self.retrytests)):
                                self.test_list.append(test)
                                test_count += 1
                                
                        # Log the results
                        if test_count > 0:
                            self.logger.info(f"Successfully generated {test_count} tests for {self.connection.upstream_str}")
                            self.logger.debug(f"Generated {len(self.test_list)} tests for {self.connection.upstream_str}")
                        else:
                            self.logger.warning(f"No tests were generated for {self.connection.upstream_str}")
                    except Exception as e:
                        self.logger.error(f"Failed to generate tests: {str(e)}")
                        self.logger.error("This may be due to certificate processing issues")
                        # Make sure we have an empty list at minimum
                        self.test_list = []
                        
                    # If we still have no tests, generate at least a self-signed test
                    if not self.test_list:
                        self.logger.warning("No tests were generated, creating a fallback self-signed test")
                        try:
                            # Generate a simple self-signed certificate as fallback
                            gen_cert, gen_key = certmitm.util.generate_certificate(cn=self.connection.upstream_sni or self.connection.upstream_ip)
                            certfile, keyfile = certmitm.util.save_certificate_chain([gen_cert], gen_key, self.working_dir, 
                                                                                   name=f"{self.connection.upstream_sni or self.connection.upstream_ip}_fallback")
                            
                            # Create a test with this certificate
                            ctx = certmitm.util.create_server_context()
                            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
                            
                            # Create a simple test object
                            test = certmitm.certtest.certtest("fallback_self_signed", 
                                                            self.connection.upstream_sni or self.connection.upstream_ip,
                                                            certfile, keyfile, None)
                            
                            # Add it to the test list
                            self.test_list.append(test)
                            self.logger.info("Successfully created fallback self-signed test")
                        except Exception as e:
                            self.logger.error(f"Failed to create fallback test: {str(e)}")
                            # We've tried our best, but we still have no tests

        # Pop next test if were are not skipping tests
        if not (self.successfull_test_list != [] and self.skiptests):
            if self.test_list:
                with self.lock:
                    if self.test_list != []:
                        return self.test_list.pop(0)

        # Get first successfull test
        if self.successfull_test_list != []:
            test = self.successfull_test_list[0]
            test.mitm = True
            return test

        # tests ran out an no successfull ones found
        return None

    def add_successfull_test(self, test):
        self.successfull_test_list.append(test)

        # Copy successfull test certs to mitmcerts
        if not os.path.exists(self.certpath):
            os.makedirs(self.certpath)
        certfilepath = os.path.join(self.certpath,f'{test.name}_cert.pem')
        keyfilepath = os.path.join(self.certpath,f'{test.name}_key.pem')
        with open(test.certfile, 'rb') as certfile:
            with open(certfilepath, 'wb') as newcertfile:
                newcertfile.write(certfile.read())
        with open(test.keyfile, 'rb') as keyfile:
            with open(keyfilepath, 'wb') as newkeyfile:
                newkeyfile.write(keyfile.read())

        # Log error to errors.txt
        filename = os.path.join(self.errorpath,'errors.txt')
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(filename, 'a') as errorfile:
            jsondata = json.dumps({"timestamp":str(time.time()),"client":self.connection.client_ip ,"destination":{"name":self.connection.upstream_name,"ip":self.connection.upstream_ip,"port":self.connection.upstream_port,"sni":self.connection.upstream_sni},"testcase":test.name,"certfile":certfilepath,"keyfile":keyfilepath,"datapath":self.mitmdatadir})
            errorfile.write(f"{jsondata}\n")

    def to_str(self):
        return(f"Identifier: {self.connection.identifier}, Upstream: {self.connection.upstream_str}, Remaining tests: {self.test_list}, Successfull tests {self.successfull_test_list}")

class mitm_connection(object):

    def __init__(self, downstream_socket, logger):
        self.logger = logger
        self.downstream_socket = downstream_socket
        self.downstream_socket.settimeout(10)
        self.downstream_tls = False
        self.downstream_tls_buf = b""

    def set_upstream(self, ip, port):
        self.logger.debug(f"Connecting to TCP upstream {ip}:{port}")
        
        # Close any existing socket first to prevent resource leaks
        if hasattr(self, 'upstream_socket') and self.upstream_socket:
            try:
                self.upstream_socket.close()
            except:
                pass
            self.upstream_socket = None
            
        # Special handling for brokedown.net
        is_special_domain = False
        if hasattr(self, 'connection') and hasattr(self.connection, 'upstream_name'):
            is_special_domain = self.connection.upstream_name == "brokedown.net"
            if is_special_domain:
                self.logger.info(f"Using special handling for connection to {ip}:{port} (brokedown.net)")
        
        # Create a new socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)  # Increased timeout for better reliability
        
        # Set TCP keepalive to detect dead connections
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Set TCP_NODELAY to disable Nagle's algorithm
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Set reuse address to avoid "address already in use" errors
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            # Connect with retry
            max_retries = 5  # Increased retries for better reliability
            retry_count = 0
            last_error = None
            
            while retry_count < max_retries:
                try:
                    # For special domains, use a longer timeout
                    if is_special_domain:
                        sock.settimeout(20)
                    
                    sock.connect((ip, port))
                    self.upstream_socket = sock
                    self.upstream_tls = False
                    self.logger.debug(f"Successfully connected to TCP upstream {ip}:{port}")
                    return
                except (ConnectionRefusedError, TimeoutError) as e:
                    retry_count += 1
                    last_error = e
                    self.logger.debug(f"Connection attempt {retry_count} failed: {e}")
                    if retry_count < max_retries:
                        # Exponential backoff for retries
                        wait_time = 0.5 * (2 ** (retry_count - 1))
                        self.logger.debug(f"Waiting {wait_time:.2f}s before retry")
                        time.sleep(wait_time)
                except OSError as e:
                    # Some OS errors might be temporary, so retry a few times
                    if e.errno in [9, 104, 110, 111]:  # Bad file descriptor, Connection reset, Connection timed out, Connection refused
                        retry_count += 1
                        last_error = e
                        self.logger.debug(f"OS error on connection attempt {retry_count}: {e}")
                        if retry_count < max_retries:
                            wait_time = 0.5 * (2 ** (retry_count - 1))
                            self.logger.debug(f"Waiting {wait_time:.2f}s before retry")
                            time.sleep(wait_time)
                    else:
                        # Don't retry on other OS errors
                        last_error = e
                        self.logger.error(f"Non-recoverable OS error: {e}")
                        break
            
            # If we get here, all retries failed
            self.logger.warning(f"Upstream connection to {ip}:{port} failed after {retry_count} attempts: {last_error}")
            try:
                sock.close()  # Make sure to close the socket on error
            except:
                pass
            self.upstream_socket = None
        except Exception as e:
            self.logger.error(f"Unexpected error connecting to upstream {ip}:{port}: {e}")
            try:
                sock.close()
            except:
                pass
            self.upstream_socket = None

    def wrap_downstream(self, context):
        self.logger.debug(f"Wrapping downstream with TLS")
        self.downstream_socket = context.wrap_socket(self.downstream_socket, server_side=True)
        self.downstream_socket.settimeout(10)
        self.downstream_tls = True
        self.logger.debug(f"Wrapped downstream with TLS")

    def wrap_upstream(self, hostname):
        self.logger.debug(f"Wrapping upstream with TLS (SNI: {hostname})")
        
        # Make sure we have a valid upstream socket
        if not self.upstream_socket:
            self.logger.error("Cannot wrap upstream with TLS: No upstream socket available")
            return False
            
        # Check if socket is already closed
        try:
            self.upstream_socket.getpeername()
        except OSError:
            self.logger.warning("Socket appears to be closed, reconnecting...")
            # Get connection details from the connection object
            if hasattr(self, 'connection'):
                try:
                    self.set_upstream(self.connection.upstream_ip, self.connection.upstream_port)
                    if not self.upstream_socket:
                        self.logger.error("Failed to reconnect upstream socket")
                        return False
                except Exception as e:
                    self.logger.error(f"Failed to reconnect: {e}")
                    return False
            else:
                self.logger.error("Cannot reconnect: No connection information available")
                return False
            
        try:
            # Create a client context with appropriate settings - completely unverified
            self.upstream_context = certmitm.util.create_client_context()
            
            # Log that we're connecting without certificate validation
            self.logger.debug(f"Connecting to upstream server without certificate validation")
            
            # Special handling for brokedown.net
            is_special_domain = hostname == "brokedown.net"
            if is_special_domain:
                self.logger.info(f"Using special handling for {hostname}")
            
            # Wrap the socket with TLS - using SNI but not validating the certificate
            try:
                # Set a reasonable timeout before wrapping
                self.upstream_socket.settimeout(15)
                
                self.upstream_socket = self.upstream_context.wrap_socket(
                    self.upstream_socket, 
                    server_hostname=hostname,  # Send SNI but don't validate against it
                    do_handshake_on_connect=True
                )
            except ssl.SSLEOFError as eof_error:
                # Handle unexpected EOF during handshake
                self.logger.warning(f"SSL EOF error during handshake: {eof_error}")
                
                # Reconnect the socket before trying again
                if hasattr(self, 'connection'):
                    try:
                        self.set_upstream(self.connection.upstream_ip, self.connection.upstream_port)
                        if not self.upstream_socket:
                            self.logger.error("Failed to reconnect upstream socket after EOF")
                            return False
                    except Exception as e:
                        self.logger.error(f"Failed to reconnect after EOF: {e}")
                        return False
                
                # Try again with do_handshake_on_connect=False and manual handshake
                self.upstream_socket = self.upstream_context.wrap_socket(
                    self.upstream_socket, 
                    server_hostname=hostname,
                    do_handshake_on_connect=False
                )
                
                # Perform handshake with a timeout
                self.upstream_socket.settimeout(15)
                try:
                    self.upstream_socket.do_handshake()
                except Exception as handshake_error:
                    self.logger.error(f"Handshake failed: {handshake_error}")
                    if self.upstream_socket:
                        try:
                            self.upstream_socket.close()
                        except:
                            pass
                        self.upstream_socket = None
                    return False
            
            # Set a timeout for TLS operations
            self.upstream_socket.settimeout(15)
            
            # Mark as TLS-wrapped
            self.upstream_tls = True
            
            # Log successful connection
            cipher = self.upstream_socket.cipher()
            if cipher:
                self.logger.debug(f"TLS connection established with cipher: {cipher[0]}")
            
            self.logger.debug(f"Successfully wrapped upstream with TLS (SNI: {hostname})")
            return True
        except ssl.SSLError as e:
            self.logger.error(f"SSL error wrapping upstream with TLS: {e}")
            
            # Try one more time with a completely unverified context
            try:
                self.logger.debug("Retrying with completely unverified context")
                
                # Reconnect the socket before trying again
                if hasattr(self, 'connection'):
                    try:
                        self.set_upstream(self.connection.upstream_ip, self.connection.upstream_port)
                        if not self.upstream_socket:
                            self.logger.error("Failed to reconnect upstream socket before retry")
                            return False
                    except Exception as e:
                        self.logger.error(f"Failed to reconnect before retry: {e}")
                        return False
                
                # Create a raw context with no verification at all
                raw_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                raw_context.check_hostname = False
                raw_context.verify_mode = ssl.CERT_NONE
                raw_context.set_ciphers('ALL')
                
                # Wrap the socket
                self.upstream_socket.settimeout(15)
                self.upstream_socket = raw_context.wrap_socket(
                    self.upstream_socket,
                    server_hostname=hostname,
                    do_handshake_on_connect=True
                )
                
                # Set a timeout for TLS operations
                self.upstream_socket.settimeout(15)
                
                # Mark as TLS-wrapped
                self.upstream_tls = True
                
                self.logger.debug(f"Successfully wrapped upstream with fallback TLS method")
                return True
            except Exception as retry_error:
                self.logger.error(f"Retry also failed: {retry_error}")
                # Close the socket on error
                if self.upstream_socket:
                    try:
                        self.upstream_socket.close()
                    except:
                        pass
                    self.upstream_socket = None
                return False
        except Exception as e:
            self.logger.error(f"Error wrapping upstream with TLS: {e}")
            # Close the socket on error
            if self.upstream_socket:
                try:
                    self.upstream_socket.close()
                except:
                    pass
                self.upstream_socket = None
            return False
