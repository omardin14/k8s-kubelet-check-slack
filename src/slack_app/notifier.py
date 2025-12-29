"""
Slack Notifier Module

Handles sending kubelet scan results to Slack with proper formatting.
"""

import os
import json
import time
import logging
from typing import Optional, Dict, Any
from pathlib import Path

from .client import SlackClient
from .formatter import SlackFormatter

logger = logging.getLogger(__name__)


class SlackNotifier:
    """Handles sending kubelet scan results to Slack."""
    
    def __init__(self, client: SlackClient):
        """
        Initialize the Slack notifier.
        
        Args:
            client: SlackClient instance for API interactions
        """
        self.client = client
        self.formatter = SlackFormatter()
    
    def send_kubelet_report(self, scan_data: Dict[str, Any], analysis: Dict[str, Any] = None,
                           channel: Optional[str] = None) -> Dict[str, Any]:
        """
        Send a formatted kubelet security report to Slack.
        
        Args:
            scan_data: Kubelet scan results
            analysis: Kubelet analysis results (optional)
            channel: Channel to send to (defaults to DEFAULT_CHANNEL)
        
        Returns:
            Response from Slack API
        """
        # Extract summary information
        summary = self.formatter.parse_kubelet_summary(scan_data)
        
        # Create rich blocks for the report
        blocks = self.formatter.create_kubelet_blocks(summary, analysis)
        
        # Create fallback text
        fallback_text = f"🔐 Kubernetes Kubelet Security Check - {summary['total_nodes']} nodes, {summary['nodes_with_issues']} with issues"
        
        try:
            response = self.client.send_rich_message(
                channel=channel,
                text=fallback_text,
                blocks=blocks
            )
            logger.info(f"Kubelet report sent successfully to {channel or self.client.default_channel}")
            return response
            
        except Exception as e:
            logger.error(f"Error sending kubelet report: {e}")
            raise
    
    def send_test_message(self, channel: Optional[str] = None) -> Dict[str, Any]:
        """
        Send a test message to verify Slack connection.
        
        Args:
            channel: Channel to send to (defaults to DEFAULT_CHANNEL)
        
        Returns:
            Response from Slack API
        """
        try:
            # Send simple test message
            response = self.client.send_message(
                "🧪 Test message from Kubernetes kubelet checker! 🔐",
                channel=channel
            )
            
            # Send rich test message
            blocks = self.formatter.create_test_blocks()
            self.client.send_rich_message(blocks, channel=channel)
            
            logger.info(f"Test messages sent successfully to {channel or self.client.default_channel}")
            return response
            
        except Exception as e:
            logger.error(f"Error sending test message: {e}")
            raise
    
    def monitor_for_scan_output(self, output_dir: str, max_wait_time: int = 300,
                                channel: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Monitor for kubelet scan output file and send report when available.
        
        Args:
            output_dir: Directory to monitor for scan results
            max_wait_time: Maximum time to wait for scan results (seconds)
            channel: Channel to send to (defaults to DEFAULT_CHANNEL)
        
        Returns:
            Response from Slack API if scan results found, None otherwise
        """
        output_path = Path(output_dir)
        results_file = output_path / "kubelet-scan-results.json"
        
        logger.info(f"Monitoring for scan results at {results_file} (max wait: {max_wait_time}s)...")
        
        start_time = time.time()
        check_interval = 5  # Check every 5 seconds
        
        while time.time() - start_time < max_wait_time:
            if results_file.exists():
                logger.info(f"✅ Scan results found at {results_file}")
                
                try:
                    # Load scan results
                    with open(results_file, 'r') as f:
                        scan_data = json.load(f)
                    
                    # Send report
                    return self.send_kubelet_report(scan_data, channel=channel)
                    
                except Exception as e:
                    logger.error(f"Error processing scan results: {e}")
                    return None
            
            time.sleep(check_interval)
        
        logger.warning(f"⏱️  Timeout waiting for scan results after {max_wait_time}s")
        return None

