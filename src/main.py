"""
Main Entry Point

Entry point for the Kubernetes kubelet security check Slack integration application.
"""

import os
import sys
from app import KubeletCheckApp
from utils import Config, setup_logging

def main():
    """Main entry point."""
    # Determine mode based on environment variables
    sidecar_mode = os.getenv('SIDECAR_MODE', 'false').lower() == 'true'
    test_mode = os.getenv('TEST_MODE', 'false').lower() == 'true'
    
    try:
        # Load configuration
        config = Config()
        
        # Set up logging
        setup_logging(level=config.log_level, debug=config.is_debug())
        
        # Initialize app
        app = KubeletCheckApp(config)
        
        # Run in appropriate mode
        if test_mode:
            exit_code = app.run_test_mode()
        elif sidecar_mode:
            exit_code = app.run_sidecar_mode()
        else:
            exit_code = app.run_scan_mode()
        
        sys.exit(exit_code)
        
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

