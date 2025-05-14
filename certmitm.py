#!/usr/bin/python3

import struct, OpenSSL, re, socket, argparse, os, random, sys, datetime, ssl, shutil, select, copy, time

import os
import _thread
import tempfile, json
import logging, threading
import resource
import selectors

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
                # Make sure to clean up the socket before returning
                if mitm_connection and mitm_connection.downstream_socket:
                    try:
                        mitm_connection.downstream_socket.close()
                    except:
                        pass
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
        insecure_data_client = b""  # Data from client
        insecure_data_server = b""  # Data from server
        insecure_data = b""         # Combined data (for backward compatibility)
        logged_insecure = False
        mitm_success = False        # Flag to track successful MITM

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
                
                # Create a selector for this iteration
                sel = selectors.DefaultSelector()
                
                # Register the sockets with the selector
                try:
                    # Always register the downstream socket
                    sel.register(mitm_connection.downstream_socket, selectors.EVENT_READ, "client")
                    
                    # Register the upstream socket if it exists
                    if mitm_connection.upstream_socket:
                        sel.register(mitm_connection.upstream_socket, selectors.EVENT_READ, "server")
                    elif not mitm_connection.downstream_tls:
                        # If we don't have an upstream socket and we're not doing TLS interception,
                        # there's nothing we can do
                        logger.debug("Could not connect to upstream on TCP mitm")
                        return
                    
                    # Wait for activity on any of the sockets (1 second timeout)
                    ready_events = sel.select(timeout=1)
                    
                    # If no events are ready, continue to the next iteration
                    if not ready_events:
                        continue
                    
                except (ValueError, OSError) as e:
                    # Handle any selector errors
                    logger.error(f"Selector error: {e}")
                    # Close the selector to free resources
                    sel.close()
                    # If we can't use the selector, we can't continue
                    return
                
                # Process the ready events
                for key, _ in ready_events:
                    ready_socket = key.fileobj
                    socket_type = key.data  # "client" or "server"
                    logger.debug(ready_socket)
                    if ready_socket == mitm_connection.downstream_socket:
                        # Lets read data from the client
                        try:
                            # Read the initial chunk
                            from_client = mitm_connection.downstream_socket.recv(4096)
                            
                            # If we have data and there might be more
                            if from_client and len(from_client) == 4096:
                                # Set socket to non-blocking to read any remaining data
                                mitm_connection.downstream_socket.setblocking(False)
                                
                                # Try to read more data until we get less than 4096 bytes
                                try:
                                    while True:
                                        # Try to read more data
                                        more_data = mitm_connection.downstream_socket.recv(4096)
                                        if not more_data:
                                            break
                                        from_client += more_data
                                        if len(more_data) < 4096:
                                            break
                                except (BlockingIOError, ssl.SSLWantReadError):
                                    # No more data available right now
                                    pass
                                finally:
                                    # Set socket back to blocking mode
                                    mitm_connection.downstream_socket.setblocking(True)
                                    
                            logger.debug(f"Read {len(from_client)} bytes from client")
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
                                # Extract HTTP information from the client request
                                http_info = certmitm.util.get_http_info(from_client, is_response=False)
                                
                                # Log HTTP information if this is an HTTP request
                                if http_info["is_http"]:
                                    request_info = ""
                                    if "status_line" in http_info:
                                        request_info = f"Request: {http_info['status_line']}"
                                    
                                    content_info = ""
                                    if "content_type" in http_info:
                                        content_info = f"Content-Type: {http_info['content_type']}"
                                    if "content_length" in http_info:
                                        content_info += f", Length: {http_info['content_length']}"
                                    elif "body_size" in http_info:
                                        content_info += f", Body size: {http_info['body_size']}"
                                    
                                    # Log the HTTP request details
                                    logger.info(f"Client request: {request_info} | {content_info}")
                                    
                                    # Add HTTP info to the log data
                                    connection_tests.log(connection, 'client_http_info', json.dumps(http_info))
                                
                                # Always store client data
                                insecure_data_client += from_client
                                insecure_data += from_client
                                
                                if not mitm:
                                    if not logged_insecure:
                                        # Insecure connection! GG happy bounties, Lets log this and add the tests to successfull test list for future mitm
                                        logger.critical(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = data intercepted!")
                                        connection_tests.add_successfull_test(connection, test)
                                        logged_insecure = True
                                        mitm_success = True
                                        
                                        # Log HTTP request details if available
                                        if http_info["is_http"] and "status_line" in http_info:
                                            logger.critical(f"HTTP Request: {http_info['status_line']}")
                                            if "content_type" in http_info:
                                                logger.critical(f"Content-Type: {http_info['content_type']}")
                                
                                # Always log client data for successful tests
                                connection_tests.log(connection, 'client', from_client)
                                
                                # If this is a successful MITM, also log with a special tag
                                if mitm_success:
                                    connection_tests.log(connection, 'client_mitm_success', from_client)
                                    
                            elif mitm:
                                # If we're in MITM mode, log the data even if it's part of the handshake
                                connection_tests.log(connection, 'client', from_client)

                        if from_client and not mitm and not args.instant_mitm: 
                            # If we don't have instant mitm, lets not send anything to server
                            logger.debug("not sending to upstream when not mitm")
                        else:
                            if mitm_connection.upstream_socket and from_client and len(from_client) > 0:
                                try:
                                    logger.debug(f"sending {len(from_client)} bytes to server")
                                    mitm_connection.upstream_socket.send(from_client)
                                except (BrokenPipeError, ConnectionResetError) as e:
                                    logger.warning(f"Failed to send data to server: {e}")
                                    break
                        count = 0
                    elif ready_socket == mitm_connection.upstream_socket:
                        # Lets read data from the server
                        try:
                            # Read the initial chunk
                            from_server = mitm_connection.upstream_socket.recv(4096)
                            
                            # If we have data and there might be more
                            if from_server and len(from_server) == 4096:
                                # Set socket to non-blocking to read any remaining data
                                mitm_connection.upstream_socket.setblocking(False)
                                
                                # Try to read more data until we get less than 4096 bytes
                                try:
                                    while True:
                                        # Try to read more data
                                        more_data = mitm_connection.upstream_socket.recv(4096)
                                        if not more_data:
                                            break
                                        from_server += more_data
                                        if len(more_data) < 4096:
                                            break
                                except (BlockingIOError, ssl.SSLWantReadError):
                                    # No more data available right now
                                    pass
                                finally:
                                    # Set socket back to blocking mode
                                    mitm_connection.upstream_socket.setblocking(True)
                                    
                            logger.debug(f"Read {len(from_server)} bytes from server")
                        except TimeoutError:
                            count = 1
                            from_server = b''
                        logger.debug(f"server: {from_server}")
                        if from_server:
                            # Extract HTTP information from the server response
                            http_info = certmitm.util.get_http_info(from_server, is_response=True)
                            
                            # Log HTTP information if this is an HTTP response
                            if http_info["is_http"]:
                                status_info = ""
                                if "status_code" in http_info:
                                    status_info = f"Status: {http_info['status_code']}"
                                    if "status_message" in http_info:
                                        status_info += f" {http_info['status_message']}"
                                
                                content_info = ""
                                if "content_type" in http_info:
                                    content_info = f"Content-Type: {http_info['content_type']}"
                                if "content_length" in http_info:
                                    content_info += f", Length: {http_info['content_length']}"
                                elif "body_size" in http_info:
                                    content_info += f", Body size: {http_info['body_size']}"
                                
                                # Log the HTTP response details
                                logger.info(f"Server response: {status_info} | {content_info}")
                                
                                # Add HTTP info to the log data
                                connection_tests.log(connection, 'server_http_info', json.dumps(http_info))
                            
                            # Always log server responses for analysis
                            connection_tests.log(connection, 'server', from_server)
                            
                            # Always store server data when it's available
                            insecure_data_server += from_server
                            insecure_data += from_server
                            
                            # If this is a successful MITM, log with a special tag
                            if mitm_success:
                                logger.critical(f"MITM SUCCESS - Captured server response: {len(from_server)} bytes")
                                if http_info["is_http"] and "status_code" in http_info:
                                    logger.critical(f"HTTP Status: {http_info.get('status_code')} {http_info.get('status_message', '')}")
                                    if "content_type" in http_info:
                                        logger.critical(f"Content-Type: {http_info['content_type']}")
                                connection_tests.log(connection, 'server_mitm_success', from_server)
                        if from_server == b'':
                            if mitm or args.instant_mitm:
                                break
                            else:
                                logger.debug("not sending b'' to client when not in mitm")
                                continue
                        else:
                            count = 0
                            
                        # Only send data to client if we have valid data
                        if from_server and len(from_server) > 0:
                            try:
                                logger.debug(f"sending {len(from_server)} bytes to client")
                                mitm_connection.downstream_socket.send(from_server)
                            except (BrokenPipeError, ConnectionResetError) as e:
                                logger.warning(f"Failed to send data to client: {e}")
                                break
                    else:
                        # We should never arrive here
                        logger.exception(f"Selector returned unknown connection")
                
                # Always close the selector at the end of each iteration to free resources
                sel.close()
                
                # If we processed data, break the loop
                if ready_events:
                    break
                else:
                    continue
            else:
                logger.debug("mitm timeout")
        except (ConnectionResetError, ssl.SSLEOFError, TimeoutError, ValueError, OSError) as e:
            # We might get this depending on the TLS implementation or socket issues
            if isinstance(e, ValueError) and "filedescriptor out of range" in str(e):
                logger.error(f"Socket descriptor error: {e}")
                logger.error("This can happen with very high socket numbers. Using selectors module to handle this.")
            elif mitm_connection.downstream_tls and not insecure_data:
                logger.info(f"{connection.client_ip}: {connection.upstream_str} for test {test.name} = Nothing received, someone closed connection")
        except Exception as e:
            # Something unexpected happened
            logger.exception(e)
        finally:
            logger.debug("Connection handling complete, cleaning up")
            
            # Only proceed with logging if we have a valid connection and test
            if 'connection' in locals() and 'test' in locals() and test:
                # Log insecure data
                if insecure_data or insecure_data_client or insecure_data_server:
                    # Log summary of what was captured
                    client_size = len(insecure_data_client)
                    server_size = len(insecure_data_server)
                    total_size = len(insecure_data)
                    
                    if mitm_success:
                        logger.critical(f"MITM SUCCESS - {connection.client_ip}: {connection.upstream_str} for test {test.name}")
                        logger.critical(f"Captured: Client: {client_size} bytes, Server: {server_size} bytes, Total: {total_size} bytes")
                        logger.critical(f"Data saved to: {connection.client_ip}/{connection.upstream_name}/data/{connection.timestamp}.*")
                    
                    # Format the data for display if requested
                    if args.show_data or args.show_data_all:
                        try:
                            # Process client data if available
                            if insecure_data_client:
                                client_str = insecure_data_client.decode('utf-8', errors='replace')
                                client_str = ''.join(c if c.isprintable() or c in '\n\r\t' else f'\\x{ord(c):02x}' for c in client_str)
                                
                                # Add a header to show data size
                                client_header = f"[Client data: {client_size} bytes] "
                                
                                # Determine how much to show
                                max_console_output = 8192 if args.show_data else float('inf')  # No limit for show_data_all
                                
                                if len(client_str) > max_console_output and not args.show_data_all:
                                    truncated_data = client_str[:max_console_output]
                                    truncated_data += f"\n[...truncated, {len(client_str) - max_console_output} more bytes...]"
                                    logger.critical(f"CLIENT REQUEST: {client_header}\n{truncated_data}")
                                else:
                                    logger.critical(f"CLIENT REQUEST: {client_header}\n{client_str}")
                            
                            # Process server data if available
                            if insecure_data_server:
                                server_str = insecure_data_server.decode('utf-8', errors='replace')
                                server_str = ''.join(c if c.isprintable() or c in '\n\r\t' else f'\\x{ord(c):02x}' for c in server_str)
                                
                                # Add a header to show data size
                                server_header = f"[Server data: {server_size} bytes] "
                                
                                # Determine how much to show
                                max_console_output = 8192 if args.show_data else float('inf')  # No limit for show_data_all
                                
                                if len(server_str) > max_console_output and not args.show_data_all:
                                    truncated_data = server_str[:max_console_output]
                                    truncated_data += f"\n[...truncated, {len(server_str) - max_console_output} more bytes...]"
                                    logger.critical(f"SERVER RESPONSE: {server_header}\n{truncated_data}")
                                else:
                                    logger.critical(f"SERVER RESPONSE: {server_header}\n{server_str}")
                                    
                        except Exception as e:
                            # Fallback to hex representation if decoding fails
                            logger.critical(f"Binary data captured - Client: {client_size} bytes, Server: {server_size} bytes")
                            
                            # Show hex dump of client data
                            if insecure_data_client and (args.show_data_all or args.show_data):
                                hex_dump = ' '.join(f'{b:02x}' for b in insecure_data_client[:1024])
                                if len(insecure_data_client) > 1024:
                                    hex_dump += f" ... [{len(insecure_data_client) - 1024} more bytes]"
                                logger.critical(f"Client hex dump: {hex_dump}")
                            
                            # Show hex dump of server data
                            if insecure_data_server and (args.show_data_all or args.show_data):
                                hex_dump = ' '.join(f'{b:02x}' for b in insecure_data_server[:1024])
                                if len(insecure_data_server) > 1024:
                                    hex_dump += f" ... [{len(insecure_data_server) - 1024} more bytes]"
                                logger.critical(f"Server hex dump: {hex_dump}")
                
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
