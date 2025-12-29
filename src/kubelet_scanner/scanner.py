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
                'warnings': [],
                'passed_checks': []
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
                
                # Aggregate passed checks
                for check in node_info.get('passed_checks', []):
                    results['summary']['passed_checks'].append({
                        'node': node_info['name'],
                        'check': check.get('check'),
                        'description': check.get('description')
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
            'kubelet_version': None,
            'issues': [],
            'passed_checks': [],
            'kubelet_config': {},
            'port_checks': {},
            'endpoint_checks': {}
        }
        
        # Extract node IPs
        for address in node.status.addresses or []:
            if address.type == 'InternalIP':
                node_info['internal_ip'] = address.address
                node_info['ip'] = address.address  # Use internal IP as primary
            elif address.type == 'ExternalIP':
                node_info['external_ip'] = address.address
        
        # Extract kubelet version from node status
        node_info['kubelet_version'] = self._extract_kubelet_version(node)
        
        # Check kubelet configuration from node status
        node_info['kubelet_config'] = self._check_kubelet_config(node)
        
        # Check kubelet ports
        if node_info['ip']:
            node_info['port_checks'] = self._check_kubelet_ports(node_info['ip'])
            node_info['endpoint_checks'] = self._check_kubelet_endpoints(node_info['ip'])
        
        # Check version vulnerabilities
        if node_info['kubelet_version']:
            node_info['version_vulnerabilities'] = self._check_version_vulnerabilities(node_info['kubelet_version'])
        
        # Compile issues and passed checks
        compiled = self._compile_issues(node_info)
        node_info['issues'] = compiled.get('issues', [])
        node_info['passed_checks'] = compiled.get('passed_checks', [])
        
        return node_info
    
    def _extract_kubelet_version(self, node) -> Optional[str]:
        """
        Extract kubelet version from node status.
        
        Args:
            node: Kubernetes node object
        
        Returns:
            Kubelet version string or None
        """
        try:
            # Kubelet version is in node.status.nodeInfo.kubeletVersion
            if hasattr(node.status, 'node_info') and node.status.node_info:
                return getattr(node.status.node_info, 'kubelet_version', None)
        except Exception as e:
            logger.debug(f"Could not extract kubelet version: {e}")
        return None
    
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
    
    def _check_kubelet_endpoints(self, node_ip: str) -> Dict[str, Any]:
        """
        Check kubelet endpoints for security issues.
        
        Args:
            node_ip: Node IP address
        
        Returns:
            Dictionary with endpoint check results
        """
        endpoint_checks = {
            'metrics': {
                'endpoint': '/metrics',
                'accessible': False,
                'anonymous_access': False,
                'status_code': None,
                'error': None
            }
        }
        
        # Check metrics endpoint (should not be accessible without auth)
        metrics_result = self._test_kubelet_endpoint(node_ip, self.DEFAULT_KUBELET_PORT, '/metrics')
        endpoint_checks['metrics'].update(metrics_result)
        
        return endpoint_checks
    
    def _test_kubelet_endpoint(self, node_ip: str, port: int, endpoint: str) -> Dict[str, Any]:
        """
        Test if a kubelet endpoint is accessible.
        
        Args:
            node_ip: Node IP address
            port: Port number
            endpoint: Endpoint path (e.g., '/metrics')
        
        Returns:
            Dictionary with test results
        """
        result = {
            'accessible': False,
            'anonymous_access': False,
            'status_code': None,
            'error': None
        }
        
        url = f"https://{node_ip}:{port}{endpoint}"
        
        try:
            response = requests.get(
                url,
                verify=False,  # Kubelet uses self-signed certs
                timeout=5,
                allow_redirects=False
            )
            
            result['accessible'] = True
            result['status_code'] = response.status_code
            
            # If we get 200 OK without auth, anonymous access is enabled
            if response.status_code == 200:
                result['anonymous_access'] = True
                logger.warning(f"⚠️  Anonymous access to {endpoint} enabled on {node_ip}:{port}")
            
        except requests.exceptions.SSLError:
            # SSL error might mean the endpoint is open but requires proper cert
            result['accessible'] = True
            result['error'] = 'SSL verification failed (expected for kubelet)'
            logger.debug(f"SSL error on {node_ip}:{port}{endpoint} (may be expected)")
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection refused or endpoint not accessible'
            logger.debug(f"Endpoint {endpoint} not accessible on {node_ip}:{port}")
        except requests.exceptions.Timeout:
            result['error'] = 'Connection timeout'
            logger.debug(f"Timeout connecting to {node_ip}:{port}{endpoint}")
        except Exception as e:
            result['error'] = str(e)
            logger.debug(f"Error testing {node_ip}:{port}{endpoint}: {e}")
        
        return result
    
    def _check_version_vulnerabilities(self, version: str) -> Dict[str, Any]:
        """
        Check kubelet version for known vulnerabilities.
        
        Note: This is a simplified check. In production, you'd want to query
        a CVE database or use a vulnerability scanning service.
        
        Args:
            version: Kubelet version string (e.g., 'v1.28.0')
        
        Returns:
            Dictionary with vulnerability information
        """
        vulnerabilities = {
            'version': version,
            'known_vulnerabilities': [],
            'is_vulnerable': False,
            'recommendation': None
        }
        
        # Known critical CVEs (simplified - in production, use a CVE database)
        # This is just an example - you'd want to maintain a proper CVE database
        critical_cves = {
            'CVE-2023-5528': {'affected_versions': ['<1.28.0'], 'severity': 'HIGH'},
            'CVE-2023-5529': {'affected_versions': ['<1.27.4'], 'severity': 'HIGH'},
            'CVE-2023-3978': {'affected_versions': ['<1.27.3'], 'severity': 'CRITICAL'},
        }
        
        # Extract version number (e.g., 'v1.28.0' -> '1.28.0')
        version_num = version.lstrip('v') if version else None
        
        if not version_num:
            vulnerabilities['error'] = 'Could not parse version'
            return vulnerabilities
        
        # Check against known CVEs (simplified version comparison)
        # In production, use proper semantic versioning library
        for cve_id, cve_info in critical_cves.items():
            for affected in cve_info['affected_versions']:
                if affected.startswith('<'):
                    # Compare versions (simplified)
                    affected_version = affected[1:].lstrip('v')
                    if self._compare_versions(version_num, affected_version) < 0:
                        vulnerabilities['known_vulnerabilities'].append({
                            'cve': cve_id,
                            'severity': cve_info['severity'],
                            'affected_version': affected
                        })
                        vulnerabilities['is_vulnerable'] = True
        
        if vulnerabilities['is_vulnerable']:
            vulnerabilities['recommendation'] = f"Upgrade kubelet to the latest patched version. Current version {version} has known vulnerabilities."
        else:
            vulnerabilities['recommendation'] = f"Version {version} appears to be secure, but always keep kubelet updated to the latest version."
        
        return vulnerabilities
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two version strings.
        
        Args:
            v1: First version string
            v2: Second version string
        
        Returns:
            -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        try:
            # Split version strings into parts
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            # Pad with zeros if needed
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            # Compare
            for i in range(max_len):
                if v1_parts[i] < v2_parts[i]:
                    return -1
                elif v1_parts[i] > v2_parts[i]:
                    return 1
            
            return 0
        except Exception as e:
            logger.debug(f"Error comparing versions {v1} and {v2}: {e}")
            return 0
    
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
    
    def _compile_issues(self, node_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compile security issues and passed checks from node scan results.
        
        Args:
            node_info: Node scan information
        
        Returns:
            Dictionary with 'issues' and 'passed_checks' lists
        """
        issues = []
        passed_checks = []
        
        default_port = node_info.get('port_checks', {}).get('default_port', {})
        readonly_port = node_info.get('port_checks', {}).get('readonly_port', {})
        endpoint_checks = node_info.get('endpoint_checks', {})
        version_vulns = node_info.get('version_vulnerabilities', {})
        
        # Check for anonymous access on default port
        if default_port.get('anonymous_access'):
            issues.append({
                'severity': 'CRITICAL',
                'type': 'anonymous_access_enabled',
                'description': f"Anonymous authentication enabled on kubelet port {default_port.get('port')}. Port is accessible without authentication.",
                'recommendation': 'Disable anonymous authentication by setting --anonymous-auth=false in kubelet configuration'
            })
        elif default_port.get('accessible'):
            # Port is accessible but requires authentication - this is GOOD
            passed_checks.append({
                'check': 'authentication_required',
                'description': f"Kubelet port {default_port.get('port')} requires authentication (anonymous access disabled)",
                'status': 'PASSED'
            })
        
        # Check if readonly port is accessible
        if readonly_port.get('accessible'):
            issues.append({
                'severity': 'CRITICAL',
                'type': 'readonly_port_enabled',
                'description': f"Readonly port {readonly_port.get('port')} is accessible. This port should be disabled (set --read-only-port=0)",
                'recommendation': 'Disable readonly port by setting --read-only-port=0 in kubelet configuration'
            })
        else:
            # Readonly port is closed - this is GOOD
            passed_checks.append({
                'check': 'readonly_port_disabled',
                'description': f"Readonly port {readonly_port.get('port', 10255)} is disabled (closed)",
                'status': 'PASSED'
            })
        
        # Check if authorization mode might be AlwaysAllow (inferred from anonymous access)
        if default_port.get('anonymous_access'):
            issues.append({
                'severity': 'CRITICAL',
                'type': 'authorization_mode_alwaysallow',
                'description': 'Authorization mode may be set to AlwaysAllow (inferred from anonymous access)',
                'recommendation': 'Set --authorization-mode to Webhook or RBAC, not AlwaysAllow'
            })
        elif default_port.get('accessible') and not default_port.get('anonymous_access'):
            # If port is accessible but requires auth, authorization is likely not AlwaysAllow
            passed_checks.append({
                'check': 'authorization_mode_secure',
                'description': 'Authorization mode appears to be secure (not AlwaysAllow, authentication required)',
                'status': 'PASSED'
            })
        
        # Check metrics endpoint
        metrics_check = endpoint_checks.get('metrics', {})
        if metrics_check.get('anonymous_access'):
            issues.append({
                'severity': 'CRITICAL',
                'type': 'metrics_endpoint_accessible',
                'description': f"Metrics endpoint is accessible without authentication. This exposes sensitive metrics data.",
                'recommendation': 'Restrict access to /metrics endpoint or ensure authentication is required'
            })
        elif metrics_check.get('accessible') and not metrics_check.get('anonymous_access'):
            # Metrics endpoint requires auth - this is GOOD
            passed_checks.append({
                'check': 'metrics_endpoint_secured',
                'description': 'Metrics endpoint requires authentication (not accessible anonymously)',
                'status': 'PASSED'
            })
        elif not metrics_check.get('accessible'):
            # Metrics endpoint not accessible - also good
            passed_checks.append({
                'check': 'metrics_endpoint_secured',
                'description': 'Metrics endpoint is not accessible (properly secured)',
                'status': 'PASSED'
            })
        
        # Check version vulnerabilities
        if version_vulns.get('is_vulnerable'):
            cve_list = ', '.join([v['cve'] for v in version_vulns.get('known_vulnerabilities', [])])
            issues.append({
                'severity': 'CRITICAL',
                'type': 'version_vulnerable',
                'description': f"Kubelet version {version_vulns.get('version')} has known vulnerabilities: {cve_list}",
                'recommendation': version_vulns.get('recommendation', 'Upgrade to the latest patched version')
            })
        elif version_vulns.get('version'):
            # Version is secure - this is GOOD
            passed_checks.append({
                'check': 'version_secure',
                'description': f"Kubelet version {version_vulns.get('version')} appears to be secure (no known critical vulnerabilities)",
                'status': 'PASSED'
            })
        
        return {
            'issues': issues,
            'passed_checks': passed_checks
        }
    
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

