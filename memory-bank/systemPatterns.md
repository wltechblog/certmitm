# certmitm System Patterns

## Architecture Overview

certmitm follows a modular architecture with clear separation of concerns:

```
                  +----------------+
                  |  Main Script   |
                  | (certmitm.py)  |
                  +-------+--------+
                          |
          +---------------+---------------+
          |               |               |
+---------v---------+ +---v---+ +---------v---------+
|  Connection       | | Util  | |  Certificate      |
|  Management       | |       | |  Testing          |
+-------------------+ +-------+ +-------------------+
```

## Core Components

### 1. Main Script (certmitm.py)
- Entry point for the application
- Handles command-line arguments
- Sets up the listening server
- Manages connection threads
- Coordinates the testing process

### 2. Connection Management (connection.py)
- Manages client and server connections
- Tracks connection state
- Handles TLS wrapping
- Maintains test lists for each connection
- Logs intercepted data

### 3. Certificate Testing (certtest.py)
- Generates test certificates
- Implements various certificate attack techniques
- Creates SSL contexts for testing
- Manages certificate chains

### 4. Utilities (util.py)
- Provides helper functions
- Handles SNI extraction
- Manages logging
- Creates SSL contexts
- Retrieves server certificates

## Key Design Patterns

### 1. Proxy Pattern
The core functionality uses a proxy pattern to intercept and potentially modify communication between clients and servers.

### 2. Factory Pattern
Certificate tests are generated using a factory pattern that creates different test scenarios based on the target connection.

### 3. Observer Pattern
The system observes connections and logs events when vulnerabilities are detected.

### 4. Thread-per-Connection Pattern
Each client connection is handled in a separate thread to allow concurrent testing.

## Data Flow

1. **Connection Interception**:
   - Client connects to the proxy
   - Original destination is extracted
   - Connection details are logged

2. **Test Generation**:
   - Server certificate is retrieved
   - Test certificates are generated
   - Test contexts are created

3. **Certificate Testing**:
   - Each test is applied to the connection
   - Client responses are monitored
   - Successful attacks are recorded

4. **Data Interception**:
   - When a vulnerability is found, data is intercepted
   - Intercepted data is logged
   - Connection can be maintained for continued interception

5. **Reporting**:
   - Successful attacks are reported
   - Intercepted data is saved
   - Results are displayed to the user

## Security Considerations

- The tool is designed for security testing only
- All intercepted data is handled securely
- Proper permissions are required for network interception
- Results should be used responsibly for vulnerability disclosure