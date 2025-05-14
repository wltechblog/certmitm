# certmitm Technical Context

## Technology Stack

### Core Technologies
- **Python 3.10+**: Primary programming language
- **OpenSSL**: Used for certificate operations and TLS connections
- **Linux Networking**: Required for connection interception

### Key Dependencies
- **pyOpenSSL**: Python wrapper for OpenSSL
- **dpkt**: Network packet parsing library

### Development Environment
- **Operating System**: Debian 11/12 (Linux)
- **Python Environment**: Standard Python environment
- **Network Configuration**: Requires network routing capabilities

## Technical Components

### Certificate Operations
- **Certificate Generation**: Creates test certificates for various attack scenarios
- **Certificate Manipulation**: Modifies certificates to test validation vulnerabilities
- **Certificate Chains**: Manages certificate chains for complex testing scenarios

### Network Interception
- **Socket Handling**: Low-level socket operations for connection interception
- **TLS Wrapping**: Wraps connections in TLS for secure communication
- **Routing**: Uses iptables for traffic redirection

### Testing Framework
- **Test Generation**: Dynamically generates tests based on target connections
- **Test Execution**: Applies tests to connections and monitors results
- **Result Tracking**: Records successful attacks and intercepted data

### Logging and Reporting
- **Console Output**: Real-time reporting of test results
- **File Logging**: Saves intercepted data and test results
- **Data Analysis**: Tools for analyzing intercepted data

## Technical Constraints

### Platform Limitations
- **Operating System**: Primarily designed for Linux
- **Network Access**: Requires network routing capabilities
- **Permissions**: Needs elevated permissions for network operations

### Performance Considerations
- **Concurrency**: Handles multiple connections concurrently
- **Memory Usage**: Manages certificate generation and storage efficiently
- **Network Throughput**: Minimizes impact on connection performance

### Security Requirements
- **Data Handling**: Securely manages intercepted data
- **Certificate Storage**: Properly handles sensitive certificate material
- **Access Control**: Requires appropriate permissions for operation

## Technical Setup

### Installation Requirements
1. Python 3.10 or higher
2. Required Python packages (via pip)
3. Network routing capabilities
4. Real certificates for advanced testing

### Network Configuration
```bash
# Example network configuration
sudo ip addr add 10.0.0.1/24 dev eth0
sudo dnsmasq --no-daemon --interface eth0 --dhcp-range=10.0.0.100,10.0.0.200 --log-dhcp --log-queries --bind-interfaces -C /dev/null
sudo iptables -A INPUT -i eth0 -j ACCEPT
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 9900
sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
```

### Certificate Requirements
- Real certificates should be placed in the `real_certs` directory
- Certificate and key files must be in PEM format
- Filenames should follow the pattern: `name_cert.pem` and `name_key.pem`

## Integration Points

### Input
- TLS connections from client applications
- Command-line arguments for configuration
- Certificate files for testing

### Output
- Console logs of test results
- Saved intercepted data
- Detailed test reports

### External Systems
- Client devices and applications
- Target servers
- Network infrastructure