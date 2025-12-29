"""
Kubelet Analyzer Module

Analyzes kubelet scan results and provides insights with OpenAI-powered risk analysis.
"""

import logging
import os
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class KubeletAnalyzer:
    """Analyzes kubelet scan results and provides risk insights."""
    
    def __init__(self, openai_api_key: Optional[str] = None, openai_model: str = "gpt-4"):
        """
        Initialize the kubelet analyzer.
        
        Args:
            openai_api_key: OpenAI API key (optional, for AI-powered analysis)
            openai_model: OpenAI model to use (default: gpt-4)
        """
        self.openai_api_key = openai_api_key or os.getenv('OPENAI_API_KEY')
        self.openai_model = openai_model
        self.openai_enabled = self.openai_api_key is not None
    
    def analyze_results(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze kubelet scan results and provide insights.
        
        Args:
            scan_results: Kubelet scan results dictionary
            
        Returns:
            Analysis results with recommendations and AI-powered insights
        """
        logger.info("🔍 Analyzing kubelet scan results...")
        
        analysis = {
            'overall_status': scan_results.get('status', 'UNKNOWN'),
            'critical_risks': scan_results.get('summary', {}).get('critical_issues', []),
            'warnings': scan_results.get('summary', {}).get('warnings', []),
            'recommendations': [],
            'summary': scan_results.get('summary', {}),
            'node_analyses': []
        }
        
        nodes = scan_results.get('nodes', [])
        
        # Analyze each node
        for node in nodes:
            node_analysis = self._analyze_node(node)
            analysis['node_analyses'].append(node_analysis)
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        # Get AI-powered insights if enabled
        if self.openai_enabled:
            try:
                ai_insights = self._get_ai_insights(analysis)
                analysis['ai_insights'] = ai_insights
            except Exception as e:
                logger.warning(f"Failed to get AI insights: {e}")
                analysis['ai_insights'] = None
        else:
            analysis['ai_insights'] = None
        
        return analysis
    
    def _analyze_node(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single node's kubelet configuration.
        
        Args:
            node: Node scan information
        
        Returns:
            Node analysis results
        """
        issues = node.get('issues', [])
        critical_count = sum(1 for issue in issues if issue.get('severity') == 'CRITICAL')
        warning_count = sum(1 for issue in issues if issue.get('severity') == 'WARNING')
        
        if critical_count > 0:
            risk_level = 'high'
        elif warning_count > 0:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'name': node.get('name'),
            'ip': node.get('ip'),
            'risk_level': risk_level,
            'issues': issues,
            'port_checks': node.get('port_checks', {})
        }
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """
        Generate security recommendations based on scan results.
        
        Args:
            analysis: Analysis results
        
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Check for anonymous access
        for risk in analysis.get('critical_risks', []):
            if 'anonymous' in risk.get('issue', '').lower():
                recommendations.append(
                    "Disable anonymous authentication on kubelet by setting --anonymous-auth=false"
                )
        
        # Check for readonly port
        for risk in analysis.get('critical_risks', []):
            if 'readonly' in risk.get('issue', '').lower():
                recommendations.append(
                    "Disable readonly port by setting --read-only-port=0 in kubelet configuration"
                )
        
        # General recommendations
        if analysis.get('critical_risks'):
            recommendations.append(
                "Review and harden kubelet security configuration on all nodes"
            )
            recommendations.append(
                "Ensure kubelet ports are not exposed to the internet"
            )
        
        if not recommendations:
            recommendations.append("No critical issues found. Continue monitoring kubelet security.")
        
        return recommendations
    
    def _get_ai_insights(self, analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Get AI-powered insights using OpenAI.
        
        Args:
            analysis: Analysis results
        
        Returns:
            AI insights dictionary
        """
        try:
            from openai import OpenAI
            
            client = OpenAI(api_key=self.openai_api_key)
            
            # Build prompt
            prompt = self._build_ai_prompt(analysis)
            
            response = client.chat.completions.create(
                model=self.openai_model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a Kubernetes security expert. Analyze kubelet security scan results and provide detailed risk assessment and remediation recommendations."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=1000
            )
            
            ai_text = response.choices[0].message.content
            
            return {
                'analysis': ai_text,
                'model': self.openai_model
            }
            
        except Exception as e:
            logger.error(f"Error getting AI insights: {e}")
            return None
    
    def _build_ai_prompt(self, analysis: Dict[str, Any]) -> str:
        """
        Build prompt for AI analysis.
        
        Args:
            analysis: Analysis results
        
        Returns:
            Prompt string
        """
        prompt = f"""Analyze the following kubelet security scan results:

Status: {analysis.get('overall_status', 'UNKNOWN')}
Total Nodes: {analysis.get('summary', {}).get('total_nodes', 0)}
Nodes with Issues: {analysis.get('summary', {}).get('nodes_with_issues', 0)}

Critical Issues:
"""
        for risk in analysis.get('critical_risks', [])[:5]:
            prompt += f"- {risk.get('issue', 'Unknown issue')}\n"
        
        prompt += "\nWarnings:\n"
        for warning in analysis.get('warnings', [])[:5]:
            prompt += f"- {warning.get('issue', 'Unknown warning')}\n"
        
        prompt += """
Please provide:
1. Overall risk assessment with severity
2. Top 3-5 critical security concerns with business impact
3. WHY IT'S DANGEROUS - Attack vectors and potential exploits
4. EXPLANATION - What attackers could do with these vulnerabilities
5. Prioritized remediation roadmap with time estimates
"""
        
        return prompt

