"""
AI Assistant Integration Module
Supports multiple AI providers via API keys
"""

import requests
import json
from typing import Dict, Any, List, Optional
from enum import Enum


class AIProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    OLLAMA = "ollama"
    GROQ = "groq"
    CUSTOM = "custom"


class AIAssistant:
    def __init__(self, provider: str, api_key: str = None, base_url: str = None):
        """
        Initialize AI Assistant
        
        Args:
            provider: AI provider (openai, anthropic, google, ollama, groq, custom)
            api_key: API key for the provider (not needed for Ollama)
            base_url: Custom base URL (for Ollama or custom providers)
        """
        self.provider = provider.lower()
        self.api_key = api_key
        self.base_url = base_url or self._get_default_url()
        
    def _get_default_url(self) -> str:
        """Get default API URL for provider"""
        urls = {
            "openai": "https://api.openai.com/v1/chat/completions",
            "anthropic": "https://api.anthropic.com/v1/messages",
            "google": "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent",
            "ollama": "http://localhost:11434/api/generate",
            "groq": "https://api.groq.com/openai/v1/chat/completions",
        }
        return urls.get(self.provider, "")
        
    def analyze_vulnerability(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a vulnerability finding using AI
        
        Returns:
            - explanation: Plain English explanation
            - risk_assessment: Business impact analysis
            - exploitation_scenario: How an attacker might exploit it
            - remediation_priority: Priority level with justification
        """
        prompt = self._build_vulnerability_prompt(finding)
        response = self._call_ai(prompt)
        
        return {
            "explanation": response.get("explanation", ""),
            "risk_assessment": response.get("risk_assessment", ""),
            "exploitation_scenario": response.get("exploitation_scenario", ""),
            "remediation_priority": response.get("remediation_priority", ""),
            "ai_confidence": response.get("confidence", 0)
        }
        
    def suggest_remediation(self, finding: Dict[str, Any], tech_stack: List[str] = None) -> Dict[str, Any]:
        """
        Get AI-powered remediation suggestions
        
        Args:
            finding: Vulnerability finding
            tech_stack: List of technologies used (e.g., ['Python', 'Django', 'PostgreSQL'])
            
        Returns:
            - code_fix: Specific code changes
            - configuration_changes: Config file updates
            - best_practices: General recommendations
            - testing_steps: How to verify the fix
        """
        prompt = self._build_remediation_prompt(finding, tech_stack)
        response = self._call_ai(prompt)
        
        return {
            "code_fix": response.get("code_fix", ""),
            "configuration_changes": response.get("configuration_changes", ""),
            "best_practices": response.get("best_practices", []),
            "testing_steps": response.get("testing_steps", [])
        }
        
    def recommend_learning_path(self, vulnerability_type: str, skill_level: str = "beginner") -> Dict[str, Any]:
        """
        Get personalized learning recommendations
        
        Args:
            vulnerability_type: Type of vulnerability (e.g., 'sql_injection')
            skill_level: User's skill level (beginner, intermediate, advanced)
            
        Returns:
            - learning_path: Ordered list of resources
            - practice_labs: Hands-on exercises
            - estimated_time: Time to master
        """
        prompt = f"""
You are a cybersecurity education expert. Create a personalized learning path for understanding and exploiting {vulnerability_type}.

Skill Level: {skill_level}

Provide:
1. Step-by-step learning path (tutorials, courses, documentation)
2. Hands-on practice labs (CTF challenges, vulnerable apps)
3. Estimated time to achieve proficiency
4. Key concepts to master
5. Common pitfalls to avoid

Format as JSON.
"""
        response = self._call_ai(prompt)
        
        return {
            "learning_path": response.get("learning_path", []),
            "practice_labs": response.get("practice_labs", []),
            "estimated_time": response.get("estimated_time", ""),
            "key_concepts": response.get("key_concepts", []),
            "pitfalls": response.get("pitfalls", [])
        }
        
    def explain_finding(self, finding: Dict[str, Any], audience: str = "technical") -> str:
        """
        Explain a finding in plain language
        
        Args:
            finding: Vulnerability finding
            audience: Target audience (technical, executive, beginner)
            
        Returns:
            Plain language explanation
        """
        prompt = f"""
Explain this security vulnerability to a {audience} audience:

Vulnerability: {finding.get('name')}
Type: {finding.get('vulnerability_type')}
CVSS Score: {finding.get('cvss_score')}
Location: {finding.get('url')}

Evidence:
{json.dumps(finding.get('evidence', {}), indent=2)}

Provide a clear, {audience}-friendly explanation of:
1. What the vulnerability is
2. Why it's dangerous
3. What an attacker could do
4. How to fix it

Keep it concise and avoid jargon for non-technical audiences.
"""
        response = self._call_ai(prompt)
        return response.get("explanation", "")
        
    def _build_vulnerability_prompt(self, finding: Dict[str, Any]) -> str:
        """Build prompt for vulnerability analysis"""
        return f"""
You are a senior security researcher. Analyze this vulnerability finding:

Vulnerability: {finding.get('name')}
Type: {finding.get('vulnerability_type')}
CWE: {finding.get('cwe_id')}
CVSS Score: {finding.get('cvss_score')}
Severity: {finding.get('severity')}
URL: {finding.get('url')}
Confidence: {finding.get('confidence')}%

Evidence:
{json.dumps(finding.get('evidence', {}), indent=2)}

Provide a comprehensive analysis in JSON format:
{{
    "explanation": "Plain English explanation of the vulnerability",
    "risk_assessment": "Business impact and risk analysis",
    "exploitation_scenario": "Detailed attack scenario",
    "remediation_priority": "Priority level (Critical/High/Medium/Low) with justification",
    "confidence": 0-100
}}
"""
        
    def _build_remediation_prompt(self, finding: Dict[str, Any], tech_stack: List[str]) -> str:
        """Build prompt for remediation suggestions"""
        tech_info = f"\nTechnology Stack: {', '.join(tech_stack)}" if tech_stack else ""
        
        return f"""
You are a security engineer. Provide specific remediation guidance for this vulnerability:

Vulnerability: {finding.get('name')}
Type: {finding.get('vulnerability_type')}
Location: {finding.get('url')}
{tech_info}

Evidence:
{json.dumps(finding.get('evidence', {}), indent=2)}

Provide remediation guidance in JSON format:
{{
    "code_fix": "Specific code changes with examples",
    "configuration_changes": "Configuration file updates",
    "best_practices": ["List of best practices"],
    "testing_steps": ["Steps to verify the fix"]
}}
"""
        
    def _call_ai(self, prompt: str) -> Dict[str, Any]:
        """Call AI provider API"""
        try:
            if self.provider == "openai":
                return self._call_openai(prompt)
            elif self.provider == "anthropic":
                return self._call_anthropic(prompt)
            elif self.provider == "google":
                return self._call_google(prompt)
            elif self.provider == "ollama":
                return self._call_ollama(prompt)
            elif self.provider == "groq":
                return self._call_groq(prompt)
            elif self.provider == "custom":
                return self._call_custom(prompt)
            else:
                return {"error": f"Unsupported provider: {self.provider}"}
        except Exception as e:
            return {"error": str(e)}
            
    def _call_openai(self, prompt: str) -> Dict[str, Any]:
        """Call OpenAI API"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert assistant."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "response_format": {"type": "json_object"}
        }
        
        response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        content = result["choices"][0]["message"]["content"]
        
        try:
            return json.loads(content)
        except:
            return {"explanation": content}
            
    def _call_anthropic(self, prompt: str) -> Dict[str, Any]:
        """Call Anthropic Claude API"""
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 2048,
            "messages": [
                {"role": "user", "content": prompt}
            ]
        }
        
        response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        content = result["content"][0]["text"]
        
        try:
            return json.loads(content)
        except:
            return {"explanation": content}
            
    def _call_google(self, prompt: str) -> Dict[str, Any]:
        """Call Google Gemini API"""
        url = f"{self.base_url}?key={self.api_key}"
        
        data = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }
        
        response = requests.post(url, json=data, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        content = result["candidates"][0]["content"]["parts"][0]["text"]
        
        try:
            return json.loads(content)
        except:
            return {"explanation": content}
            
    def _call_ollama(self, prompt: str) -> Dict[str, Any]:
        """Call Ollama (local) API"""
        data = {
            "model": "llama3.2",
            "prompt": prompt,
            "stream": False
        }
        
        response = requests.post(self.base_url, json=data, timeout=60)
        response.raise_for_status()
        
        result = response.json()
        content = result.get("response", "")
        
        try:
            return json.loads(content)
        except:
            return {"explanation": content}

    def _call_groq(self, prompt: str) -> Dict[str, Any]:
        """Call Groq API (OpenAI compatible)"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        data = {
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert assistant. You must respond in JSON format."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.4,
            "response_format": {"type": "json_object"}
        }
        
        response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        content = result["choices"][0]["message"]["content"]
        
        try:
            return json.loads(content)
        except:
            return {"explanation": content}
            
    def _call_custom(self, prompt: str) -> Dict[str, Any]:
        """Call custom API endpoint"""
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            
        data = {"prompt": prompt}
        
        response = requests.post(self.base_url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        
        return response.json()
        
    def test_connection(self) -> Dict[str, Any]:
        """Test AI provider connection"""
        try:
            response = self._call_ai("Say 'Connection successful' in JSON format: {\"status\": \"success\"}")
            return {
                "success": True,
                "provider": self.provider,
                "response": response
            }
        except Exception as e:
            return {
                "success": False,
                "provider": self.provider,
                "error": str(e)
            }
