# certmitm Project Brief

## Project Overview
certmitm is a security testing tool designed to identify and exploit TLS certificate validation vulnerabilities in client applications and devices. It works by intercepting HTTPS connections and attempting various certificate-based attacks to determine if the client properly validates certificates.

## Core Functionality
1. Intercepts TLS connections between clients and servers
2. Tests multiple certificate validation bypass techniques
3. Logs successful attacks and captured data
4. Provides detailed reporting on vulnerable connections

## Key Components
- Certificate generation and manipulation
- TLS connection interception
- Man-in-the-middle attack simulation
- Logging and reporting of vulnerable connections

## Technical Requirements
- Python 3.10+
- Linux environment (tested on Debian 11/12)
- Network routing capabilities
- Real certificates for advanced testing

## Success Criteria
The tool successfully identifies applications and devices that:
- Accept self-signed certificates
- Accept certificates with replaced keys
- Accept certificates from unauthorized CAs
- Have other TLS certificate validation vulnerabilities

## Constraints
- Requires network routing setup to intercept connections
- Needs real certificates for comprehensive testing
- Limited to TLS/HTTPS connections

## Project Goals
1. Provide a reliable tool for security researchers to test certificate validation
2. Help identify vulnerable applications and devices
3. Raise awareness about certificate validation vulnerabilities
4. Support responsible disclosure of identified vulnerabilities