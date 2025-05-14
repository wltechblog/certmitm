#!/usr/bin/python3

import struct, OpenSSL, re, socket, argparse, os, random, sys, datetime, ssl, shutil, select, copy, time

import os
import _thread
import tempfile, json
import logging, threading
import resource

import certmitm.util
import certmitm.certtest
import certmitm.connection

description = r"""
               _             _ _               _                                     
              | |           (_) |             | |                                    
  ___ ___ _ __| |_ _ __ ___  _| |_ _ __ ___   | |__  _   _    __ _  __ _ _ __   ___  
 / __/ _ \ '__| __| '_ ` _ \| | __| '_ ` _ \  | '_ \| | | |  / _` |/ _` | '_ \ / _ \ 
| (_|  __/ |  | |_| | | | | | | |_| | | | | | | |_) | |_| | | (_| | (_| | |_) | (_) |
 \___\___|_|   \__|_| |_| |_|_|\__|_| |_| |_| |_.__/ \__, |  \__,_|\__,_| .__/ \___/ 
                                                      __/ |             | |          
                                                     |___/              |_|          

A tool for testing for certificate validation vulnerabilities of TLS connections made by a client device or an application.

Created by Aapo Oksman - https://github.com/AapoOksman/certmitm - MIT License
"""

# Handle command line flags/arguments
def handle_args():
    parser = argparse.ArgumentParser(description=description, prog="certmitm.py", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbosity.', default=False)
    parser.add_argument('--instant-mitm', action='store_true', help='Forward intercepted data before all tests are completed', default=False)
    parser.add_argument('--skip-additional-tests', action='store_true', help='Use first successfull test to mitm without trying any others.', default=False)
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug verbosity', default=False)
    #parser.add_argument('--pre-generate', nargs=2, help="Pre-generate server certificates for a specific hostname.", metavar=("HOSTNAME", "DIRECTORY")) #not yet implemented
    parser.add_argument('-w', '--workdir', nargs=1, help='Set the working directory', metavar="DIRECTORY")
    parser.add_argument('-l', '--listen', nargs=1, help="Listen for a connection", metavar="PORT")
    parser.add_argument('-r', '--retrytests', nargs=1, help="How many times each test is run", default="1")
    parser.add_argument('-s', '--show-data', action="store_true", help="Log the intercepted data to console. Trunkates to a sensible length", default=False)
    parser.add_argument('--show-data-all', action="store_true", help="Log all of the intercepted data to console. Not recommended as large amounts of data will mess up your console.", default=False)
    #parser.add_argument('--upstream-proxy', nargs=1, help="Upstream proxy for MITM. For example, BURP (127.0.0.1:8080)", metavar="ADDRESS") #not yet implemented
    return parser.parse_args()

def threaded_connection_handler(downstream_socket, listen_port):
    # Set thread name for better logging
    threading.current_thread().name = f"Thread-{threading.get_ident()}"
    
    # Use the custom VERBOSE level if it exists, otherwise fall back to INFO
    verbose_level = 15 if hasattr(logging, 'VERBOSE') else logging.INFO
    
    mitm_connection = None
    try:
        global connection_tests

        # Lets start by initializing a mitm_connection object with the client connection
        mitm_connection = certmitm.connection.mitm_connection(downstream_socket, logger)
        connection = certmitm.connection.connection(mitm_connection.downstream_socket, logger, listen_port)
        logger.log(verbose_level, f"Got connection: {connection.to_str()}")

        # Check if this is a connection loop
        if connection.is_loop:
            logger.warning(f"Detected connection loop: {connection.to_str()}")
            logger.warning("This could be caused by incorrect network configuration or routing.")
            logger.warning("Make sure your iptables rules don't redirect traffic back to the proxy.")
            
            # For testing purposes, we can still try to connect to a different port
            if connection.upstream_port == 10000:
                logger.log(verbose_level, f"Attempting to connect to test port 10000 instead")
            else:
                # In production, we should just close the connection
                logger.warning("Closing connection to prevent infinite loop")
                return
        
        # Lets get a test for the client
        test = connection_tests.get_test(connection)
        if not test:
            # No tests available, lets just do a TCP mitm :(
            logger.log(verbose_level, f"Can't mitm {connection.identifier}. Forwarding plain tcp")
            try:
                mitm_connection.set_upstream(connection.upstream_ip, connection.upstream_port)
            except OSError as e:
                logger.log(verbose_level, f"Can't connect to {connection.identifier}: {e}")
                return
        else:
            # We have a test to run
            logger.log(verbose_level, f"Next test is: {test.to_str()}")
            try:
                # Lets try to wrap the client connection to TLS
                mitm_connection.wrap_downstream(test.context)
            except (ssl.SSLError, ConnectionResetError, BrokenPipeError, TimeoutError) as e:
                logger.info(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = {e}")
                return
            mitm_connection.set_upstream(connection.upstream_ip, connection.upstream_port)
            if mitm_connection.upstream_socket:
                try:
                    mitm_connection.wrap_upstream(connection.upstream_sni)
                except (ssl.SSLZeroReturnError, TimeoutError) as e:
                    logger.log(verbose_level, f"Cannot wrap upstream socket: {e}. Destroying also the TCP socket.")
                    if mitm_connection.upstream_socket:
                        mitm_connection.upstream_socket.close()
                    mitm_connection.upstream_socket = None
            if not mitm_connection.upstream_socket:
                logger.info(f"Cannot connect to {connection.upstream_ip}: with TLS, still trying to intercept without mitm.")

        from_client = None
        from_server = None
        insecure_data = b""
        logged_insecure = False

        if test:
            mitm = test.mitm
        else:
            mitm = True

        logger.debug(f"mitm {mitm}")
        count = 0

        # Lets mitm, The upstream and downstream might be either TLS or TCP
        try:
            while count < 5:
                count += 1
                logger.debug(f"count {count}")
                # Lets see if the client or the server wants to talk to us
                if mitm_connection.upstream_socket:
                    ready = select.select([mitm_connection.downstream_socket, mitm_connection.upstream_socket], [], [], 1)
                else:
                    if mitm_connection.downstream_tls:
                        # Only do one party mitm if we're trying to intercept TLS
                        logger.debug("Connecting only to the client and not upstream")
                        ready = select.select([mitm_connection.downstream_socket], [], [], 1)
                    else:
                        logger.debug("Could not connect to upstream on TCP mitm")
                        return

                for ready_socket in ready[0]:
                    logger.debug(ready_socket)
                    if ready_socket == mitm_connection.downstream_socket:
                        # Lets read data from the client
                        try:
                            from_client = mitm_connection.downstream_socket.recv(4096)
                        except TimeoutError:
                            count = 5
                            break
                        logger.debug(f"client: {from_client}")
                        if from_client == b'':
                            count = 5
                            break
                        if from_client and mitm_connection.downstream_tls:
                            # double check that we're not logging the TLS handshake
                            if not certmitm.util.SNIFromHello(from_client):
                                if not mitm:
                                    if not logged_insecure:
                                        # Insecure connection! GG happy bounties, Lets log this and add the tests to successfull test list for future mitm
                                        logger.critical(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = data intercepted!")
                                        connection_tests.add_successfull_test(connection, test)
                                        logged_insecure = True
                                    insecure_data += from_client
                                connection_tests.log(connection, 'client', from_client)

                        if from_client and not mitm and not args.instant_mitm: 
                            # If we don't have instant mitm, lets not send anything to server
                            logger.debug("not sending to upstream when not mitm")
                        else:
                            if mitm_connection.upstream_socket:
                                mitm_connection.upstream_socket.send(from_client)
                                logger.debug(f"sending to server: {from_client}")
                        count = 0
                    elif ready_socket == mitm_connection.upstream_socket:
                        # Lets read data from the server
                        try:
                            from_server = mitm_connection.upstream_socket.recv(4096)
                        except TimeoutError:
                            count = 1
                            from_server = b''
                        logger.debug(f"server: {from_server}")
                        if from_server and mitm_connection.upstream_tls:
                            if not mitm:
                                insecure_data += from_server
                            connection_tests.log(connection, 'server', from_server)
                        if from_server == b'':
                            if mitm or args.instant_mitm:
                                break
                            else:
                                logger.debug("not sending b'' to client when not in mitm")
                                continue
                        else:
                            count = 0
                        mitm_connection.downstream_socket.send(from_server)
                        logger.debug(f"sending to client: {from_server}")
                    else:
                        # We should never arrive here
                        logger.exception(f"Select returned unknown connection")
                else:
                    continue
                break
            else:
                logger.debug("mitm timeout")
        except (ConnectionResetError, ssl.SSLEOFError, TimeoutError):
            # We might get this depending on the TLS implementation
            if mitm_connection.downstream_tls and not insecure_data:
                logger.info(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = Nothing received, someone closed connection")
        except Exception as e:
            # Something unexpected happened
            logger.exception(e)
        finally:
            logger.debug("Connection handling complete, cleaning up")
            
            # Only proceed with logging if we have a valid connection and test
            if 'connection' in locals() and 'test' in locals() and test:
                # Log insecure data
                if insecure_data:
                    # Format the data for better display
                    try:
                        # Try to decode as UTF-8 if possible
                        data_str = insecure_data.decode('utf-8', errors='replace')
                        
                        # Clean up control characters for better display
                        data_str = ''.join(c if c.isprintable() or c in '\n\r\t' else f'\\x{ord(c):02x}' for c in data_str)
                        
                        # Add a header to show data size
                        data_size = len(insecure_data)
                        header = f"[Intercepted {data_size} bytes] "
                        
                        if args.show_data_all:
                            logger.critical(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = {header}{data_str}")
                        elif args.show_data:
                            # Truncate but show how much was truncated
                            truncated_data = data_str[:4096]
                            if len(data_str) > 4096:
                                truncated_data += f"\n[...truncated, {len(data_str) - 4096} more bytes...]"
                            logger.critical(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = {header}{truncated_data}")
                    except Exception as e:
                        # Fallback to hex representation if decoding fails
                        logger.critical(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = [Binary data, {len(insecure_data)} bytes]")
                        if args.show_data_all or args.show_data:
                            # Show hex dump of first 1024 bytes
                            hex_dump = ' '.join(f'{b:02x}' for b in insecure_data[:1024])
                            if len(insecure_data) > 1024:
                                hex_dump += f" ... [{len(insecure_data) - 1024} more bytes]"
                            logger.critical(f"Hex dump: {hex_dump}")
                
                # Log secure connections
                elif mitm_connection and mitm_connection.downstream_tls and not mitm:
                    logger.info(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = Nothing received")

            # Make sure we clean up all sockets
            if mitm_connection:
                if hasattr(mitm_connection, 'downstream_socket') and mitm_connection.downstream_socket:
                    try:
                        # Close TLS gracefully if it's a TLS socket
                        if hasattr(mitm_connection, 'downstream_tls') and mitm_connection.downstream_tls:
                            try:
                                mitm_connection.downstream_socket.unwrap()
                            except:
                                pass
                        # Close TCP socket
                        mitm_connection.downstream_socket.close()
                    except:
                        logger.debug("Error closing downstream socket")
                
                if hasattr(mitm_connection, 'upstream_socket') and mitm_connection.upstream_socket:
                    try:
                        # Close TLS gracefully if it's a TLS socket
                        if hasattr(mitm_connection, 'upstream_tls') and mitm_connection.upstream_tls:
                            try:
                                mitm_connection.upstream_socket.unwrap()
                            except:
                                pass
                        # Close TCP socket
                        mitm_connection.upstream_socket.close()
                    except:
                        logger.debug("Error closing upstream socket")
            
    except Exception as e:
        # Something really unexpected happened
        logger.exception(e)

def listen_forking(port):
    # Try to increase the file descriptor limit
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        # Try to increase to hard limit or 4096, whichever is smaller
        new_soft = min(hard, 4096)
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
        logger.info(f"Increased file descriptor limit from {soft} to {new_soft}")
    except (ImportError, ValueError, resource.error) as e:
        logger.warning(f"Could not increase file descriptor limit: {e}")
    
    # Use the custom VERBOSE level if it exists, otherwise fall back to INFO
    verbose_level = 15 if hasattr(logging, 'VERBOSE') else logging.INFO
    
    try:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Set a timeout on the listener socket to periodically check for errors
        listener.settimeout(60)
        listener.bind(("0.0.0.0", int(port)))
        listener.listen(5)
        
        logger.info(f"Listening on port {port}")
        
        active_threads = []
        
        while True:
            try:
                # Clean up completed threads
                active_threads = [t for t in active_threads if t.is_alive()]
                
                # Log the number of active threads periodically
                if len(active_threads) > 0 and len(active_threads) % 10 == 0:
                    logger.log(verbose_level, f"Currently handling {len(active_threads)} active connections")
                
                # Accept new connections
                try:
                    client, address = listener.accept()
                    client.settimeout(30)
                    logger.log(verbose_level, f"Request from: {address}")
                    
                    # Create a thread for the connection
                    thread = threading.Thread(
                        target=threaded_connection_handler, 
                        args=(client, int(port)),
                        daemon=True
                    )
                    thread.start()
                    active_threads.append(thread)
                except socket.timeout:
                    # This is just the listener timeout, continue the loop
                    continue
                
            except Exception as e:
                logger.exception(f"Error handling connection: {e}")
    except Exception as e:
        logger.exception(f"Error setting up listener: {e}")
    finally:
        if 'listener' in locals():
            try:
                listener.close()
            except:
                pass

if __name__ == '__main__':
    args = handle_args()

    logger = certmitm.util.createLogger("log")

    # Create a custom VERBOSE level between INFO and DEBUG
    VERBOSE = 15
    logging.addLevelName(VERBOSE, "VERBOSE")
    
    # Add a verbose method to the logger
    def verbose(self, message, *args, **kwargs):
        if self.isEnabledFor(VERBOSE):
            self._log(VERBOSE, message, args, **kwargs)
    
    logging.Logger.verbose = verbose
    
    # Set the appropriate log level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.verbose:
        logger.setLevel(VERBOSE)
    else:
        logger.setLevel(logging.WARNING)
        
    # Add the VERBOSE level to the formatter
    certmitm.util.LogColorFormatter.FORMATS[VERBOSE] = certmitm.util.LogColorFormatter.blue + "VERBOSE - %(message)s" + certmitm.util.LogColorFormatter.reset

    if args.workdir:
        working_dir = args.workdir[0]
    else:
        working_dir = tempfile.mkdtemp()
    if not os.path.exists(working_dir):
        os.mkdir(working_dir)

    if not len(sys.argv) > 1:
        exitstr = "see "+str(sys.argv[0])+" -h for help"
        exit(exitstr)

    if len(sys.argv) == 2:
        if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":
            exitstr = "see "+str(sys.argv[0])+" -h for help"
            exit(exitstr)

    connection_tests = certmitm.connection.connection_tests(logger, working_dir, args.retrytests[0], args.skip_additional_tests)

    if args.listen is not None:
        listen_forking(args.listen[0])
