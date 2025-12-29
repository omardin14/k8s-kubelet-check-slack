"""
Main Application Module

Main application class that orchestrates the Kubernetes kubelet security check Slack integration.
"""

import os
import logging
from typing import Optional

from slack_app import SlackClient, SlackNotifier
from kubelet_scanner import KubeletScanner, KubeletAnalyzer
from utils import Config, setup_logging

try:
    from kubernetes.client.rest import ApiException
    KUBERNETES_AVAILABLE = True
except ImportError:
    KUBERNETES_AVAILABLE = False
    ApiException = None

logger = logging.getLogger(__name__)


class KubeletCheckApp:
    """Main application class for Kubernetes kubelet security check Slack integration."""
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the application.
        
        Args:
            config: Configuration instance (optional)
        """
        self.config = config or Config()
        
        # Validate configuration
        if not self.config.validate():
            raise ValueError("Invalid configuration. SLACK_BOT_TOKEN is required.")
        
        # Set up logging
        setup_logging(debug=self.config.is_debug())
        
        # Initialize components
        self.slack_client = SlackClient(self.config.get_slack_token())
        self.slack_notifier = SlackNotifier(self.slack_client)
        self.kubelet_scanner = KubeletScanner()
        # Initialize analyzer with OpenAI if enabled
        if self.config.is_openai_enabled():
            self.kubelet_analyzer = KubeletAnalyzer(
                openai_api_key=self.config.get_openai_api_key(),
                openai_model=self.config.get_openai_model()
            )
        else:
            self.kubelet_analyzer = KubeletAnalyzer()
        
        logger.info("Kubernetes kubelet security check app initialized successfully")
    
    def run_sidecar_mode(self) -> int:
        """
        Run in sidecar mode (monitoring for kubelet scan output).
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        logger.info("🔐 Starting Kubernetes kubelet security check sidecar container")
        logger.info(f"📁 Monitoring directory: {self.config.get_output_dir()}")
        logger.info(f"📢 Target channel: {self.config.get_slack_channel()}")
        
        try:
            # Send startup notification
            self.slack_notifier.client.send_message(
                f"🚀 Kubernetes kubelet security check started! Monitoring for results...",
                self.config.get_slack_channel()
            )
            
            # Monitor for kubelet scan output and send results
            success = self.slack_notifier.monitor_for_scan_output(
                self.config.get_output_dir(),
                self.config.get_max_wait_time(),
                self.config.get_slack_channel()
            )
            
            if success:
                logger.info("✅ Kubelet scan results sent successfully")
                return 0
            else:
                logger.error("❌ Failed to send kubelet scan results")
                return 1
                
        except Exception as e:
            logger.error(f"❌ Error in sidecar mode: {e}")
            return 1
    
    def run_scan_mode(self) -> int:
        """
        Run in scan mode (perform scan and send results).
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        logger.info("🔐 Starting Kubernetes kubelet security scan...")
        
        try:
            # Perform kubelet scan
            scan_results = self.kubelet_scanner.scan_kubelet_config()
            
            # Analyze results
            analysis = self.kubelet_analyzer.analyze_results(scan_results)
            
            # Send report to Slack
            self.slack_notifier.send_kubelet_report(
                scan_results,
                analysis,
                self.config.get_slack_channel()
            )
            
            logger.info("✅ Kubelet scan completed and report sent")
            return 0
            
        except Exception as e:
            logger.error(f"❌ Error in scan mode: {e}")
            return 1
    
    def run_test_mode(self) -> int:
        """
        Run in test mode (send test message to Slack).
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        logger.info("🧪 Running in test mode...")
        
        try:
            self.slack_notifier.send_test_message(self.config.get_slack_channel())
            logger.info("✅ Test message sent successfully")
            return 0
            
        except Exception as e:
            logger.error(f"❌ Error in test mode: {e}")
            return 1

