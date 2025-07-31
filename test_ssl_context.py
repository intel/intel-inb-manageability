#!/usr/bin/env python3

import os
import tempfile
import platform

# Mock the constants and logger
LINUX_CA_FILE = '/etc/ssl/certs/ca-certificates.crt'

class MockLogger:
    def warning(self, msg):
        print(f"WARNING: {msg}")
    def debug(self, msg):
        print(f"DEBUG: {msg}")

logger = MockLogger()

def get_platform_ca_certs():
    return True

# Global list to track temporary CA files
_temp_ca_files = []

def create_ssl_context_for_requests():
    """Create appropriate certificate verification setting for requests.
    
    For test environments, tries to use a custom CA bundle that includes test certificates.
    Falls back to platform defaults if needed.
    
    @return: Certificate verification setting for requests verify parameter
    """
    try:
        # For Windows, always use default behavior
        if platform.system() == 'Windows':
            return True
        
        # For Linux, check if test CA certificate exists
        test_ca_path = '/home/nat/go/intel-inb-manageability/inbm/integration-reloaded/scripts/csl-ca-cert.pem'
        if os.path.exists(test_ca_path):
            # Create a combined CA bundle for test environments
            combined_ca_fd, combined_ca_path = tempfile.mkstemp(suffix='.pem', prefix='inbm_ca_')
            
            try:
                with os.fdopen(combined_ca_fd, 'w') as combined_ca_file:
                    # Add standard CA certificates
                    if os.path.exists(LINUX_CA_FILE):
                        try:
                            with open(LINUX_CA_FILE, 'r', encoding='utf-8') as std_ca:
                                combined_ca_file.write(std_ca.read())
                                combined_ca_file.write('\n')
                        except UnicodeDecodeError:
                            # Fallback to latin-1 encoding for binary data
                            with open(LINUX_CA_FILE, 'r', encoding='latin-1') as std_ca:
                                combined_ca_file.write(std_ca.read())
                                combined_ca_file.write('\n')
                    
                    # Add test CA certificate content if it's a valid PEM file
                    try:
                        with open(test_ca_path, 'r', encoding='utf-8') as test_ca:
                            test_content = test_ca.read().strip()
                            # Only add if it contains actual certificate content
                            if test_content and ('-----BEGIN CERTIFICATE-----' in test_content or test_content.startswith('/')):
                                if test_content.startswith('/'):
                                    # It's a path reference, try to read from that path
                                    actual_cert_path = test_content.strip()
                                    if os.path.exists(actual_cert_path):
                                        with open(actual_cert_path, 'r', encoding='utf-8') as actual_cert:
                                            combined_ca_file.write(actual_cert.read())
                                else:
                                    # It's actual certificate content
                                    combined_ca_file.write(test_content)
                                    combined_ca_file.write('\n')
                    except Exception as cert_e:
                        logger.debug(f"Could not read test CA certificate: {cert_e}")
                        # Continue without test certificate
                
                # Track the temporary file for cleanup
                _temp_ca_files.append(combined_ca_path)
                return combined_ca_path
                
            except Exception as e:
                logger.warning(f"Failed to create combined CA bundle: {e}")
                try:
                    os.unlink(combined_ca_path)
                except Exception:
                    pass
                return LINUX_CA_FILE
        else:
            # Production environment - use standard CA file
            return LINUX_CA_FILE
            
    except Exception as e:
        logger.warning(f"Failed to create custom SSL verification: {e}")
        # Fallback to default behavior
        return get_platform_ca_certs()

if __name__ == '__main__':
    print("Testing SSL context function...")
    
    # Check if test CA exists
    test_ca_path = '/home/nat/go/intel-inb-manageability/inbm/integration-reloaded/scripts/csl-ca-cert.pem'
    print(f"Test CA exists: {os.path.exists(test_ca_path)}")
    
    if os.path.exists(test_ca_path):
        print("Test CA content preview:")
        with open(test_ca_path, 'r') as f:
            lines = f.readlines()[:3]
            for line in lines:
                print(f"  {line.strip()}")
    
    # Test the SSL context function
    result = create_ssl_context_for_requests()
    print(f"SSL context result type: {type(result)}")
    print(f"SSL context result: {result}")
    
    # If result is a file path, check if it exists and show content
    if isinstance(result, str) and result.startswith('/tmp/'):
        print(f"Combined CA file exists: {os.path.exists(result)}")
        if os.path.exists(result):
            print("Combined CA content preview:")
            with open(result, 'r') as f:
                lines = f.readlines()[:5]
                for line in lines:
                    print(f"  {line.strip()}")
            
            # Check size
            size = os.path.getsize(result)
            print(f"Combined CA file size: {size} bytes")
