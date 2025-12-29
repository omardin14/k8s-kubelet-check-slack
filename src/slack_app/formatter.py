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
        
        total_nodes = summary.get('total_nodes', 0)
        nodes_with_issues = summary.get('nodes_with_issues', 0)
        healthy_nodes = total_nodes - nodes_with_issues
        critical_count = len(analysis.get('critical_risks', [])) if analysis else 0
        
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
                        "text": f"*Total Nodes:*\n`{total_nodes}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Nodes with Issues:*\n🔴 `{nodes_with_issues}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Healthy Nodes:*\n✅ `{healthy_nodes}`"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Critical Issues:*\n🔴 `{critical_count}`"
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
        
        # Add passed checks section (security good practices)
        if analysis and analysis.get('summary', {}).get('passed_checks'):
            passed_checks = analysis['summary']['passed_checks']
            if passed_checks:
                blocks.append({"type": "divider"})
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*✅ Security Checks Passed:*"
                    }
                })
                # Group by check type
                check_types = {}
                for check in passed_checks[:10]:  # Show top 10
                    check_type = check.get('check', 'unknown')
                    if check_type not in check_types:
                        check_types[check_type] = []
                    check_types[check_type].append(check.get('description', ''))
                
                for check_type, descriptions in list(check_types.items())[:5]:  # Show top 5 types
                    unique_descriptions = list(set(descriptions))[:3]  # Show up to 3 unique descriptions
                    for desc in unique_descriptions:
                        blocks.append({
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"✅ {desc}"
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
                kubelet_version = node.get('kubelet_version', 'Unknown')
                issues = node.get('issues', [])
                issues_count = len(issues)
                passed_checks = node.get('passed_checks', [])
                passed_count = len(passed_checks)
                port_checks = node.get('port_checks', {})
                version_vulns = node.get('version_vulnerabilities', {})
                
                # Determine risk level
                has_critical = any(issue.get('severity') == 'CRITICAL' for issue in issues)
                if has_critical:
                    emoji = "🔴"
                    risk_level = "HIGH"
                elif issues_count > 0:
                    emoji = "⚠️"
                    risk_level = "MEDIUM"
                else:
                    emoji = "✅"
                    risk_level = "LOW"
                
                # Build port status text
                port_status_parts = []
                default_port = port_checks.get('default_port', {})
                readonly_port = port_checks.get('readonly_port', {})
                
                if default_port.get('accessible'):
                    if default_port.get('anonymous_access'):
                        port_status_parts.append(f"Port {default_port.get('port', 10250)}: OPEN (ANONYMOUS)")
                    else:
                        port_status_parts.append(f"Port {default_port.get('port', 10250)}: OPEN (AUTH REQUIRED)")
                else:
                    port_status_parts.append(f"Port {default_port.get('port', 10250)}: CLOSED")
                
                if readonly_port.get('accessible'):
                    port_status_parts.append(f"Readonly {readonly_port.get('port', 10255)}: OPEN")
                else:
                    port_status_parts.append(f"Readonly {readonly_port.get('port', 10255)}: CLOSED")
                
                port_status = " | ".join(port_status_parts) if port_status_parts else "Port checks unavailable"
                
                # Build version status
                version_status = f"Version: {kubelet_version}"
                if version_vulns.get('is_vulnerable'):
                    version_status += " 🔴 (VULNERABLE)"
                elif kubelet_version != 'Unknown':
                    version_status += " ✅"
                
                status_text = f"{emoji} *{node_name}* (IP: {node_ip})\n*Risk:* {risk_level} | *Issues:* {issues_count}"
                if passed_count > 0:
                    status_text += f" | *Passed Checks:* {passed_count}"
                status_text += f" | {port_status}\n{version_status}"
                
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": status_text
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

