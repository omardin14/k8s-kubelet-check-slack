"""
HTML Report Generator Module

Converts kubelet scan results into a beautiful HTML report.
"""

import json
import time
import re
from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime


class HTMLReportGenerator:
    """Generates HTML reports from kubelet scan data."""
    
    @staticmethod
    def generate_kubelet_report(scan_data: Dict[str, Any], analysis: Dict[str, Any] = None,
                               output_path: str = None) -> str:
        """
        Generate a styled HTML report from kubelet scan data.
        
        Args:
            scan_data: Kubelet scan results
            analysis: Kubelet analysis results (optional)
            output_path: Optional path to save the HTML file
            
        Returns:
            HTML content as string
        """
        summary = scan_data.get('summary', {})
        nodes = scan_data.get('nodes', [])
        
        total_nodes = summary.get('total_nodes', 0)
        nodes_with_issues = summary.get('nodes_with_issues', 0)
        status = scan_data.get('status', 'UNKNOWN')
        
        # Determine overall status
        if status == 'CRITICAL':
            status_color = "#ef4444"
        elif status == 'WARNING':
            status_color = "#f59e0b"
        else:
            status_color = "#10b981"
        
        # Calculate values before f-string
        healthy_nodes = total_nodes - nodes_with_issues
        
        # Generate HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kubernetes Kubelet Security Check Report - {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        
        .header .timestamp {{
            opacity: 0.9;
            font-size: 0.9em;
        }}
        
        .status-banner {{
            background: {status_color};
            color: white;
            padding: 30px;
            text-align: center;
            font-size: 1.8em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f9fafb;
        }}
        
        .summary-card {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            text-align: center;
            transition: transform 0.2s;
        }}
        
        .summary-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        
        .summary-card .number {{
            font-size: 3em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .summary-card .label {{
            color: #6b7280;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .total {{ color: #3b82f6; }}
        .issues {{ color: #ef4444; }}
        .healthy {{ color: #10b981; }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            font-size: 1.8em;
            margin-bottom: 20px;
            color: #1f2937;
        }}
        
        .node {{
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .node-header {{
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #f9fafb;
            transition: background 0.2s;
        }}
        
        .node-header:hover {{
            background: #f3f4f6;
        }}
        
        .node-title {{
            font-size: 1.2em;
            font-weight: 600;
            color: #1f2937;
        }}
        
        .node-status {{
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9em;
        }}
        
        .status-critical {{
            background: #fee2e2;
            color: #991b1b;
        }}
        
        .status-warning {{
            background: #fef3c7;
            color: #92400e;
        }}
        
        .status-healthy {{
            background: #d1fae5;
            color: #065f46;
        }}
        
        .node-body {{
            display: none;
            padding: 20px;
        }}
        
        .node.expanded .node-body {{
            display: block;
        }}
        
        .node.expanded .node-header {{
            background: #667eea;
            color: white;
        }}
        
        .node.expanded .node-title {{
            color: white;
        }}
        
        .detail {{
            background: #f9fafb;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
            border-radius: 4px;
        }}
        
        .detail strong {{
            color: #1f2937;
            display: block;
            margin-bottom: 5px;
        }}
        
        .detail .value {{
            color: #4b5563;
            font-family: 'Courier New', monospace;
        }}
        
        .issue {{
            background: #fef2f2;
            padding: 12px;
            border-left: 4px solid #ef4444;
            border-radius: 4px;
            margin-bottom: 10px;
        }}
        
        .issue.warning {{
            background: #fef3c7;
            border-left-color: #f59e0b;
        }}
        
        .issue strong {{
            color: #991b1b;
            display: block;
            margin-bottom: 5px;
        }}
        
        .issue.warning strong {{
            color: #92400e;
        }}
        
        .recommendation {{
            background: #eff6ff;
            padding: 12px;
            border-left: 4px solid #3b82f6;
            border-radius: 4px;
            margin-top: 10px;
            color: #1e40af;
        }}
        
        .port-check {{
            background: #f9fafb;
            padding: 10px;
            margin: 5px 0;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .port-accessible {{
            color: #ef4444;
        }}
        
        .port-closed {{
            color: #10b981;
        }}
        
        .ai-insights {{
            background: #eff6ff;
            padding: 15px;
            margin-top: 15px;
            border-left: 4px solid #3b82f6;
            border-radius: 4px;
        }}
        
        .ai-insights strong {{
            color: #1e40af;
            display: block;
            margin-bottom: 10px;
        }}
        
        .ai-analysis-container {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 30px;
            margin-top: 20px;
        }}
        
        .ai-section {{
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        .ai-section:last-child {{
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }}
        
        .ai-heading {{
            color: #1e40af;
            font-size: 1.3em;
            font-weight: 700;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #3b82f6;
        }}
        
        .ai-content {{
            color: #374151;
            line-height: 1.8;
            font-size: 0.95em;
        }}
        
        .ai-content p {{
            margin-bottom: 12px;
        }}
        
        .ai-content p:last-child {{
            margin-bottom: 0;
        }}
        
        .ai-content strong {{
            color: #1e40af;
            font-weight: 600;
        }}
        
        .ai-list {{
            list-style: none;
            padding-left: 0;
            margin: 15px 0;
        }}
        
        .ai-list li {{
            padding: 10px 15px;
            margin-bottom: 8px;
            background: white;
            border-left: 4px solid #3b82f6;
            border-radius: 4px;
        }}
        
        .ai-list li:last-child {{
            margin-bottom: 0;
        }}
        
        .ai-list li strong {{
            color: #1e40af;
            display: inline-block;
            margin-right: 5px;
        }}
        
        .btn-expand {{
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            margin: 20px 0;
        }}
        
        .btn-expand:hover {{
            background: #5568d3;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .node-body {{
                display: block !important;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Kubernetes Kubelet Security Check</h1>
            <div class="timestamp">Generated: {scan_data.get('scan_time', 'Unknown')}</div>
        </div>
        
        <div class="status-banner">
            Status: {status}
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="label">Total Nodes</div>
                <div class="number total">{total_nodes}</div>
            </div>
            <div class="summary-card">
                <div class="label">Nodes with Issues</div>
                <div class="number issues">{nodes_with_issues}</div>
            </div>
            <div class="summary-card">
                <div class="label">Healthy Nodes</div>
                <div class="number healthy">{healthy_nodes}</div>
            </div>
        </div>
        
        <div class="content">
            {HTMLReportGenerator._generate_passed_checks_section(analysis)}
            {HTMLReportGenerator._generate_critical_issues_section(analysis)}
            {HTMLReportGenerator._generate_node_list(nodes)}
            {HTMLReportGenerator._generate_recommendations_section(analysis)}
            {HTMLReportGenerator._generate_ai_analysis_section(analysis)}
        </div>
    </div>
    
    <script>
        document.querySelectorAll('.node-header').forEach(header => {{
            header.addEventListener('click', function() {{
                this.parentElement.classList.toggle('expanded');
            }});
        }});
    </script>
</body>
</html>"""
        
        # Save to file if path provided
        if output_path:
            with open(output_path, 'w') as f:
                f.write(html)
        
        return html
    
    @staticmethod
    def _generate_passed_checks_section(analysis: Dict[str, Any]) -> str:
        """Generate passed security checks section."""
        if not analysis or not analysis.get('summary', {}).get('passed_checks'):
            return ""
        
        passed_checks = analysis['summary']['passed_checks']
        if not passed_checks:
            return ""
        
        checks_html = '<div class="section"><h2>✅ Security Checks Passed</h2>'
        
        # Group by check type
        check_types = {}
        for check in passed_checks:
            check_type = check.get('check', 'unknown')
            if check_type not in check_types:
                check_types[check_type] = []
            check_types[check_type].append({
                'node': check.get('node', 'Unknown'),
                'description': check.get('description', '')
            })
        
        for check_type, checks in check_types.items():
            # Show unique descriptions
            unique_descriptions = {}
            for check in checks:
                desc = check['description']
                if desc not in unique_descriptions:
                    unique_descriptions[desc] = []
                unique_descriptions[desc].append(check['node'])
            
            for desc, nodes in unique_descriptions.items():
                nodes_list = ', '.join(set(nodes))
                checks_html += f'''
                <div class="detail" style="border-left-color: #10b981; background: #d1fae5;">
                    <strong>✅ {desc}</strong>
                    <div class="value">Nodes: {nodes_list}</div>
                </div>'''
        
        checks_html += '</div>'
        return checks_html
    
    @staticmethod
    def _generate_critical_issues_section(analysis: Dict[str, Any]) -> str:
        """Generate critical issues section."""
        if not analysis or not analysis.get('critical_risks'):
            return ""
        
        issues_html = '<div class="section"><h2>🔴 Critical Issues</h2>'
        for risk in analysis['critical_risks']:
            node_name = risk.get('node', 'Unknown')
            issue_desc = risk.get('issue', 'Unknown issue')
            issues_html += f'''
            <div class="issue">
                <strong>{node_name}</strong>
                <div>{issue_desc}</div>
            </div>'''
        issues_html += '</div>'
        return issues_html
    
    @staticmethod
    def _generate_node_list(nodes: list) -> str:
        """Generate node list section."""
        if not nodes:
            return '<div class="section"><h2>📋 Nodes</h2><p>No nodes found.</p></div>'
        
        nodes_html = '<div class="section"><h2>📋 Node Details</h2>'
        
        for node in nodes:
            node_name = node.get('name', 'Unknown')
            node_ip = node.get('ip', 'N/A')
            issues = node.get('issues', [])
            issues_count = len(issues)
            port_checks = node.get('port_checks', {})
            
            # Determine status
            has_critical = any(issue.get('severity') == 'CRITICAL' for issue in issues)
            if has_critical:
                status_class = 'status-critical'
                status_text = 'CRITICAL'
            elif issues_count > 0:
                status_class = 'status-warning'
                status_text = 'WARNING'
            else:
                status_class = 'status-healthy'
                status_text = 'HEALTHY'
            
            nodes_html += f'''
            <div class="node">
                <div class="node-header">
                    <div class="node-title">{node_name} ({node_ip})</div>
                    <div class="node-status {status_class}">{status_text}</div>
                </div>
                <div class="node-body">
                    <div class="detail">
                        <strong>IP Address:</strong>
                        <div class="value">{node_ip}</div>
                    </div>
                    {HTMLReportGenerator._generate_port_checks(port_checks)}
                    {HTMLReportGenerator._generate_node_passed_checks(node.get('passed_checks', []))}
                    {HTMLReportGenerator._generate_node_issues(issues)}
                </div>
            </div>'''
        
        nodes_html += '</div>'
        return nodes_html
    
    @staticmethod
    def _generate_port_checks(port_checks: Dict[str, Any]) -> str:
        """Generate port check details."""
        if not port_checks:
            return ""
        
        html = '<div class="detail"><strong>Port Checks:</strong>'
        
        default_port = port_checks.get('default_port', {})
        readonly_port = port_checks.get('readonly_port', {})
        
        if default_port:
            port = default_port.get('port', 'N/A')
            accessible = default_port.get('accessible', False)
            anonymous = default_port.get('anonymous_access', False)
            status_class = 'port-accessible' if accessible else 'port-closed'
            status_text = 'ACCESSIBLE' if accessible else 'CLOSED'
            if anonymous:
                status_text += ' (ANONYMOUS ACCESS)'
            
            html += f'''
            <div class="port-check">
                Default Port {port}: <span class="{status_class}">{status_text}</span>
            </div>'''
        
        if readonly_port:
            port = readonly_port.get('port', 'N/A')
            accessible = readonly_port.get('accessible', False)
            status_class = 'port-accessible' if accessible else 'port-closed'
            status_text = 'ACCESSIBLE' if accessible else 'CLOSED'
            
            html += f'''
            <div class="port-check">
                Readonly Port {port}: <span class="{status_class}">{status_text}</span>
            </div>'''
        
        html += '</div>'
        return html
    
    @staticmethod
    def _generate_node_passed_checks(passed_checks: list) -> str:
        """Generate passed checks list for a node."""
        if not passed_checks:
            return ""
        
        html = '<div class="detail"><strong>✅ Security Checks Passed:</strong>'
        for check in passed_checks:
            description = check.get('description', 'Unknown check')
            html += f'''
            <div style="background: #d1fae5; border-left: 4px solid #10b981; padding: 10px; margin: 5px 0; border-radius: 4px;">
                <strong>✅ {description}</strong>
            </div>'''
        html += '</div>'
        return html
    
    @staticmethod
    def _generate_node_issues(issues: list) -> str:
        """Generate issues list for a node."""
        if not issues:
            return '<div class="detail"><strong>Issues:</strong> <div class="value">No issues found ✅</div></div>'
        
        html = '<div class="detail"><strong>Issues:</strong>'
        for issue in issues:
            severity = issue.get('severity', 'UNKNOWN')
            issue_type = issue.get('type', 'unknown')
            description = issue.get('description', 'Unknown issue')
            recommendation = issue.get('recommendation', '')
            
            issue_class = 'issue' if severity == 'CRITICAL' else 'issue warning'
            
            recommendation_html = ''
            if recommendation:
                recommendation_html = f'<div class="recommendation">💡 {recommendation}</div>'
            
            html += f'''
            <div class="{issue_class}">
                <strong>{severity}: {issue_type}</strong>
                <div>{description}</div>
                {recommendation_html}
            </div>'''
        
        html += '</div>'
        return html
    
    @staticmethod
    def _generate_recommendations_section(analysis: Dict[str, Any]) -> str:
        """Generate recommendations section."""
        if not analysis or not analysis.get('recommendations'):
            return ""
        
        html = '<div class="section"><h2>💡 Recommendations</h2>'
        for rec in analysis['recommendations']:
            html += f'<div class="recommendation">• {rec}</div>'
        html += '</div>'
        return html
    
    @staticmethod
    def _generate_ai_analysis_section(analysis: Dict[str, Any]) -> str:
        """Generate AI analysis section."""
        if not analysis or not analysis.get('ai_insights'):
            return ""
        
        ai_insights = analysis['ai_insights']
        ai_text = ai_insights.get('analysis', '')
        
        if not ai_text:
            return ""
        
        # Format the AI analysis with proper HTML structure
        formatted_assessment = HTMLReportGenerator._format_ai_analysis_text(ai_text)
        
        return f"""
        <div class="section">
            <h2>🤖 AI-Powered Risk Analysis</h2>
            <div class="ai-analysis-container">
                {formatted_assessment}
            </div>
        </div>
        """
    
    @staticmethod
    def _format_ai_analysis_text(text: str) -> str:
        """Format AI analysis text with proper HTML structure."""
        if not text:
            return ""
        
        # Split text by section headings (format: **1. Title**)
        # Use a regex that captures the heading and content separately
        pattern = r'(\*\*\d+\.\s+[^*]+\*\*)'
        parts = re.split(pattern, text)
        
        html_parts = []
        current_section = False
        
        for i, part in enumerate(parts):
            part = part.strip()
            if not part:
                continue
            
            # Check if this is a heading (starts with ** and has a number)
            if re.match(r'\*\*\d+\.', part):
                # Close previous section if exists
                if current_section:
                    html_parts.append('</div></div>')
                
                # Extract heading text (remove ** markers)
                heading_text = re.sub(r'\*\*', '', part)
                
                # Start new section
                html_parts.append(f'<div class="ai-section"><h3 class="ai-heading">{heading_text}</h3><div class="ai-content">')
                current_section = True
            else:
                # This is content - convert markdown to HTML
                formatted = HTMLReportGenerator._convert_markdown_to_html(part)
                html_parts.append(formatted)
        
        # Close last section
        if current_section:
            html_parts.append('</div></div>')
        
        result = ''.join(html_parts)
        # If no sections were found, format the whole text
        if not current_section:
            result = f'<div class="ai-content">{HTMLReportGenerator._convert_markdown_to_html(text)}</div>'
        
        return result
    
    @staticmethod
    def _convert_markdown_to_html(text: str) -> str:
        """Convert markdown-style formatting to HTML."""
        if not text:
            return ""
        
        # First, convert **bold** to <strong> (but avoid converting if it's part of a heading pattern)
        # We'll do this more carefully to avoid double conversion
        text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', text)
        
        # Split into lines for processing
        lines = text.split('\n')
        formatted_lines = []
        in_list = False
        current_paragraph = []
        
        for line in lines:
            line = line.strip()
            
            # Empty line - end current paragraph or list
            if not line:
                if in_list:
                    formatted_lines.append('</ul>')
                    in_list = False
                elif current_paragraph:
                    formatted_lines.append(f'<p>{" ".join(current_paragraph)}</p>')
                    current_paragraph = []
                continue
            
            # Check if it's a numbered list item (format: 1. item or **1. item**)
            # But not if it's already been converted to a heading
            list_match = re.match(r'(?:<strong>)?(\d+)\.\s+(.+?)(?:</strong>)?$', line)
            if list_match and not line.startswith('<h3'):
                if not in_list:
                    formatted_lines.append('<ul class="ai-list">')
                    in_list = True
                
                item_text = list_match.group(2).strip()
                # Clean up any remaining markdown
                item_text = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', item_text)
                formatted_lines.append(f'<li>{item_text}</li>')
            else:
                # Regular text - add to current paragraph
                if in_list:
                    formatted_lines.append('</ul>')
                    in_list = False
                
                # Clean up the line
                cleaned_line = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', line)
                current_paragraph.append(cleaned_line)
        
        # Close any open structures
        if in_list:
            formatted_lines.append('</ul>')
        if current_paragraph:
            formatted_lines.append(f'<p>{" ".join(current_paragraph)}</p>')
        
        result = '\n'.join(formatted_lines)
        # If nothing was formatted, return as paragraph
        if not result:
            result = f'<p>{text}</p>'
        
        return result

