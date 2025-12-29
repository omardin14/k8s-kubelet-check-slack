"""
Kubelet Scanner Module

Scans Kubernetes cluster for kubelet security configuration issues.
"""

import os
import json
import logging
import subprocess
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import urlparse
import urllib3

# Disable SSL warnings for kubelet (uses self-signed certs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    KUBERNETES_AVAILABLE = True
except ImportError as e:
    KUBERNETES_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning(f"kubernetes library not available: {e}. Install with: pip install kubernetes")

logger = logging.getLogger(__name__)


class KubeletScanner:
    """Scans Kubernetes cluster for kubelet security configuration issues."""
    
    # Default kubelet ports
    DEFAULT_KUBELET_PORT = 10250
    DEFAULT_READONLY_PORT = 10255
    
    def __init__(self):
        """Initialize the kubelet scanner."""
        self.v1 = None
        
        if KUBERNETES_AVAILABLE:
            try:
                # Try to load in-cluster config first, then kubeconfig
                try:
                    config.load_incluster_config()
                    logger.info("Loaded in-cluster Kubernetes config")
                except:
                    config.load_kube_config()
                    logger.info("Loaded kubeconfig")
                
                self.v1 = client.CoreV1Api()
            except Exception as e:
                logger.error(f"Failed to initialize Kubernetes client: {e}")
                raise
    
    def scan_kubelet_config(self) -> Dict[str, Any]:
        """
        Scan kubelet configuration for security issues.
        
        Returns:
            Dictionary containing scan results
        """
        results = {
            'scan_time': datetime.utcnow().isoformat(),
            'nodes': [],
            'summary': {
                'total_nodes': 0,
                'nodes_with_issues': 0,
                'critical_issues': [],
                'warnings': []
            }
        }
        
        if not KUBERNETES_AVAILABLE or not self.v1:
            logger.error("Kubernetes client not available")
            results['error'] = "Kubernetes client not available"
            return results
        
        try:
            # Get all nodes
            nodes = self.v1.list_node()
            results['summary']['total_nodes'] = len(nodes.items)
            
            logger.info(f"Scanning {len(nodes.items)} nodes for kubelet security issues...")
            
            for node in nodes.items:
                node_info = self._scan_node(node)
                results['nodes'].append(node_info)
                
                # Update summary
                if node_info.get('issues'):
                    results['summary']['nodes_with_issues'] += 1
                    for issue in node_info['issues']:
                        if issue.get('severity') == 'CRITICAL':
                            results['summary']['critical_issues'].append({
                                'node': node_info['name'],
                                'issue': issue['description']
                            })
                        elif issue.get('severity') == 'WARNING':
                            results['summary']['warnings'].append({
                                'node': node_info['name'],
                                'issue': issue['description']
                            })
            
            # Calculate overall status
            if results['summary']['critical_issues']:
                results['status'] = 'CRITICAL'
            elif results['summary']['warnings']:
                results['status'] = 'WARNING'
            else:
                results['status'] = 'HEALTHY'
            
        except ApiException as e:
            logger.error(f"API error scanning nodes: {e}")
            results['error'] = f"API error: {e}"
        except Exception as e:
            logger.error(f"Error scanning kubelet config: {e}")
            results['error'] = f"Error: {e}"
        
        return results
    
    def _scan_node(self, node) -> Dict[str, Any]:
        """
        Scan a single node for kubelet security issues.
        
        Args:
            node: Kubernetes node object
        
        Returns:
            Dictionary with node scan results
        """
        node_info = {
            'name': node.metadata.name,
            'ip': None,
            'internal_ip': None,
            'external_ip': None,
            'issues': [],
            'kubelet_config': {},
            'port_checks': {}
        }
        
        # Extract node IPs
        for address in node.status.addresses or []:
            if address.type == 'InternalIP':
                node_info['internal_ip'] = address.address
                node_info['ip'] = address.address  # Use internal IP as primary
            elif address.type == 'ExternalIP':
                node_info['external_ip'] = address.address
        
        # Check kubelet configuration from node status
        node_info['kubelet_config'] = self._check_kubelet_config(node)
        
        # Check kubelet ports
        if node_info['ip']:
            node_info['port_checks'] = self._check_kubelet_ports(node_info['ip'])
        
        # Compile issues
        node_info['issues'] = self._compile_issues(node_info)
        
        return node_info
    
    def _check_kubelet_config(self, node) -> Dict[str, Any]:
        """
        Check kubelet configuration from node annotations/status.
        
        Note: Direct kubelet config access may be limited. We'll check what's available
        via the Kubernetes API and node annotations.
        
        Args:
            node: Kubernetes node object
        
        Returns:
            Dictionary with kubelet configuration checks
        """
        config_info = {
            'anonymous_auth': None,  # True if enabled (security risk)
            'authorization_mode': None,  # Should not be "AlwaysAllow"
            'readonly_port': None,  # Should be 0 or undefined
            'source': 'node_annotations'  # Where we got the info from
        }
        
        # Check node annotations for kubelet configuration
        annotations = node.metadata.annotations or {}
        
        # Try to find kubelet configuration in annotations
        # Note: This may not always be available, depends on cluster setup
        for key, value in annotations.items():
            if 'kubelet' in key.lower() or 'anonymous' in key.lower():
                logger.debug(f"Found kubelet annotation: {key} = {value}")
        
        # For now, we'll rely on port checks to infer configuration
        # In a real scenario, you might need to:
        # 1. SSH into nodes and check kubelet process args
        # 2. Check kubelet config files
        # 3. Use kubelet API endpoints if accessible
        
        return config_info
    
    def _check_kubelet_ports(self, node_ip: str) -> Dict[str, Any]:
        """
        Check if kubelet ports are accessible.
        
        Args:
            node_ip: Node IP address
        
        Returns:
            Dictionary with port check results
        """
        port_checks = {
            'default_port': {
                'port': self.DEFAULT_KUBELET_PORT,
                'accessible': False,
                'anonymous_access': False,
                'error': None
            },
            'readonly_port': {
                'port': self.DEFAULT_READONLY_PORT,
                'accessible': False,
                'error': None
            }
        }
        
        # Check default kubelet port (10250)
        default_result = self._test_kubelet_port(node_ip, self.DEFAULT_KUBELET_PORT)
        port_checks['default_port'].update(default_result)
        
        # Check readonly port (10255)
        readonly_result = self._test_kubelet_port(node_ip, self.DEFAULT_READONLY_PORT)
        port_checks['readonly_port'].update(readonly_result)
        
        return port_checks
    
    def _test_kubelet_port(self, node_ip: str, port: int) -> Dict[str, Any]:
        """
        Test if a kubelet port is accessible and if anonymous access is enabled.
        
        Args:
            node_ip: Node IP address
            port: Port number to test
        
        Returns:
            Dictionary with test results
        """
        result = {
            'accessible': False,
            'anonymous_access': False,
            'status_code': None,
            'error': None
        }
        
        url = f"https://{node_ip}:{port}"
        
        try:
            # Try to access kubelet healthz endpoint without authentication
            # This will tell us if the port is open and if anonymous access is enabled
            response = requests.get(
                f"{url}/healthz",
                verify=False,  # Kubelet uses self-signed certs
                timeout=5,
                allow_redirects=False
            )
            
            result['accessible'] = True
            result['status_code'] = response.status_code
            
            # If we get 200 OK without auth, anonymous access is enabled
            if response.status_code == 200:
                result['anonymous_access'] = True
                logger.warning(f"⚠️  Anonymous access enabled on {node_ip}:{port}")
            
        except requests.exceptions.SSLError:
            # SSL error might mean the port is open but requires proper cert
            result['accessible'] = True
            result['error'] = 'SSL verification failed (expected for kubelet)'
            logger.debug(f"SSL error on {node_ip}:{port} (may be expected)")
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection refused or port closed'
            logger.debug(f"Port {port} not accessible on {node_ip}")
        except requests.exceptions.Timeout:
            result['error'] = 'Connection timeout'
            logger.debug(f"Timeout connecting to {node_ip}:{port}")
        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"Error testing {node_ip}:{port}: {e}")
        
        return result
    
    def _compile_issues(self, node_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Compile security issues from node scan results.
        
        Args:
            node_info: Node scan information
        
        Returns:
            List of security issues
        """
        issues = []
        
        # Check for anonymous access on default port
        default_port = node_info.get('port_checks', {}).get('default_port', {})
        if default_port.get('anonymous_access'):
            issues.append({
                'severity': 'CRITICAL',
                'type': 'anonymous_access_enabled',
                'description': f"Anonymous authentication enabled on kubelet port {default_port.get('port')}. Port is accessible without authentication.",
                'recommendation': 'Disable anonymous authentication by setting --anonymous-auth=false in kubelet configuration'
            })
        
        # Check if default port is accessible (even if auth required, it's a warning)
        if default_port.get('accessible') and not default_port.get('anonymous_access'):
            issues.append({
                'severity': 'WARNING',
                'type': 'port_accessible',
                'description': f"Kubelet port {default_port.get('port')} is accessible (authentication may be required)",
                'recommendation': 'Ensure proper authentication and authorization are configured. Consider restricting network access to kubelet ports.'
            })
        
        # Check if readonly port is accessible
        readonly_port = node_info.get('port_checks', {}).get('readonly_port', {})
        if readonly_port.get('accessible'):
            issues.append({
                'severity': 'CRITICAL',
                'type': 'readonly_port_enabled',
                'description': f"Readonly port {readonly_port.get('port')} is accessible. This port should be disabled (set --read-only-port=0)",
                'recommendation': 'Disable readonly port by setting --read-only-port=0 in kubelet configuration'
            })
        
        # Check if authorization mode might be AlwaysAllow (inferred from anonymous access)
        if default_port.get('anonymous_access'):
            issues.append({
                'severity': 'CRITICAL',
                'type': 'authorization_mode_alwaysallow',
                'description': 'Authorization mode may be set to AlwaysAllow (inferred from anonymous access)',
                'recommendation': 'Set --authorization-mode to Webhook or RBAC, not AlwaysAllow'
            })
        
        return issues
    
    def save_results(self, file_path: str) -> None:
        """
        Save scan results to a JSON file.
        
        Args:
            file_path: Path to save the results
        """
        results = self.scan_kubelet_config()
        
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"✅ Kubelet scan results saved to {file_path}")

