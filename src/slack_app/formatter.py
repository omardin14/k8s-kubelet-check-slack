"""
Slack Formatter Module

Handles formatting of kubelet scan results into Slack message blocks.
"""

import json
from typing import Dict, Any, List
from datetime import datetime


class SlackFormatter:
    """Formats kubelet scan results into Slack message blocks."""
    
    @staticmethod
    def parse_kubelet_summary(data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse kubelet scan data to extract summary information."""
        summary = data.get('summary', {})
        nodes = data.get('nodes', [])
        
        return {
            'total_nodes': summary.get('total_nodes', 0),
            'nodes_with_issues': summary.get('nodes_with_issues', 0),
            'scan_time': data.get('scan_time', ''),
            'status': data.get('status', 'UNKNOWN'),
            'nodes': nodes
        }
    
    @staticmethod
    def create_kubelet_blocks(summary: Dict[str, Any], analysis: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Create Slack blocks for kubelet report."""
        # Determine overall status
        status = summary.get('status', 'UNKNOWN')
        if status == 'CRITICAL':
            status_emoji = "🔴"
            status_text = "CRITICAL"
            status_color = "#ff0000"
        elif status == 'WARNING':
            status_emoji = "⚠️"
            status_text = "WARNING"
            status_color = "#ff9900"
        else:
            status_emoji = "✅"
            status_text = "HEALTHY"
            status_color = "#36a64f"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} Kubernetes Kubelet Security Check Report",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Status:* {status_text}\n*Scan Time:* {summary.get('scan_time', 'Unknown')}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Nodes:*\n`{summary['total_nodes']}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Nodes with Issues:*\n🔴 `{summary['nodes_with_issues']}`"
                    }
                ]
            }
        ]
        
        # Add critical issues section
        if analysis and analysis.get('critical_risks'):
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*🔴 Critical Issues:*"
                }
            })
            for risk in analysis['critical_risks'][:5]:  # Show top 5
                node_name = risk.get('node', 'Unknown')
                issue_desc = risk.get('issue', 'Unknown issue')
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"• *{node_name}*: {issue_desc}"
                    }
                })
        
        # Add warnings section
        if analysis and analysis.get('warnings'):
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*⚠️ Warnings:*"
                }
            })
            for warning in analysis['warnings'][:5]:  # Show top 5
                node_name = warning.get('node', 'Unknown')
                issue_desc = warning.get('issue', 'Unknown warning')
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"• *{node_name}*: {issue_desc}"
                    }
                })
        
        # Add node details
        nodes = summary.get('nodes', [])
        if nodes:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*📋 Node Details:*"
                }
            })
            
            for node in nodes[:10]:  # Show top 10
                node_name = node.get('name', 'Unknown')
                node_ip = node.get('ip', 'N/A')
                issues = node.get('issues', [])
                issues_count = len(issues)
                
                # Choose emoji based on issues
                if any(issue.get('severity') == 'CRITICAL' for issue in issues):
                    emoji = "🔴"
                elif issues_count > 0:
                    emoji = "⚠️"
                else:
                    emoji = "✅"
                
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *{node_name}* (IP: {node_ip})\n*Issues:* {issues_count}"
                    }
                })
        
        # Add recommendations
        if analysis and analysis.get('recommendations'):
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*💡 Recommendations:*"
                }
            })
            for rec in analysis['recommendations'][:5]:  # Show top 5
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"• {rec}"
                    }
                })
        
        # Add AI analysis if available
        if analysis and analysis.get('ai_insights') and analysis['ai_insights'].get('analysis'):
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*🤖 AI-Powered Risk Analysis:*"
                }
            })
            # Truncate AI analysis for Slack (it's long)
            ai_text = analysis['ai_insights']['analysis'][:1000] + "..." if len(analysis['ai_insights']['analysis']) > 1000 else analysis['ai_insights']['analysis']
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```{ai_text}```"
                }
            })
        
        return blocks
    
    @staticmethod
    def create_test_blocks() -> List[Dict[str, Any]]:
        """Create test blocks for testing Slack integration."""
        return [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🧪 Test Message from Kubernetes Kubelet Checker",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "This is a test message to verify Slack integration is working correctly."
                }
            }
        ]

