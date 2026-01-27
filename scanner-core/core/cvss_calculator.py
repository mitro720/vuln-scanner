"""
CVSS 3.1 Calculator
Common Vulnerability Scoring System implementation
"""

from typing import Dict, Any
from enum import Enum


class AttackVector(Enum):
    NETWORK = ("N", 0.85)
    ADJACENT = ("A", 0.62)
    LOCAL = ("L", 0.55)
    PHYSICAL = ("P", 0.2)


class AttackComplexity(Enum):
    LOW = ("L", 0.77)
    HIGH = ("H", 0.44)


class PrivilegesRequired(Enum):
    NONE = ("N", 0.85)
    LOW = ("L", 0.62)
    HIGH = ("H", 0.27)


class UserInteraction(Enum):
    NONE = ("N", 0.85)
    REQUIRED = ("R", 0.62)


class Scope(Enum):
    UNCHANGED = ("U", False)
    CHANGED = ("C", True)


class Impact(Enum):
    NONE = ("N", 0.0)
    LOW = ("L", 0.22)
    HIGH = ("H", 0.56)


class CVSSCalculator:
    """CVSS 3.1 Score Calculator"""
    
    def __init__(self):
        pass
        
    def calculate_base_score(
        self,
        attack_vector: str = "N",
        attack_complexity: str = "L",
        privileges_required: str = "N",
        user_interaction: str = "N",
        scope: str = "U",
        confidentiality: str = "H",
        integrity: str = "H",
        availability: str = "H"
    ) -> Dict[str, Any]:
        """
        Calculate CVSS 3.1 Base Score
        
        Args:
            attack_vector: N (Network), A (Adjacent), L (Local), P (Physical)
            attack_complexity: L (Low), H (High)
            privileges_required: N (None), L (Low), H (High)
            user_interaction: N (None), R (Required)
            scope: U (Unchanged), C (Changed)
            confidentiality: N (None), L (Low), H (High)
            integrity: N (None), L (Low), H (High)
            availability: N (None), L (Low), H (High)
            
        Returns:
            Dict with score, severity, and vector string
        """
        
        # Attack Vector values
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        
        # Attack Complexity values
        ac_values = {"L": 0.77, "H": 0.44}
        
        # User Interaction values
        ui_values = {"N": 0.85, "R": 0.62}
        
        # Impact values
        impact_values = {"N": 0.0, "L": 0.22, "H": 0.56}
        
        # Get values
        av = av_values.get(attack_vector, 0.85)
        ac = ac_values.get(attack_complexity, 0.77)
        ui = ui_values.get(user_interaction, 0.85)
        
        # Privileges Required (scope-dependent)
        if scope == "C":
            pr_values = {"N": 0.85, "L": 0.68, "H": 0.50}
        else:
            pr_values = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr = pr_values.get(privileges_required, 0.85)
        
        # Impact values
        c = impact_values.get(confidentiality, 0.56)
        i = impact_values.get(integrity, 0.56)
        a = impact_values.get(availability, 0.56)
        
        # Calculate Exploitability Sub-Score
        exploitability = 8.22 * av * ac * pr * ui
        
        # Calculate Impact Sub-Score
        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        if scope == "C":
            impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
        else:
            impact = 6.42 * isc_base
            
        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif scope == "C":
            base_score = min(1.08 * (impact + exploitability), 10.0)
        else:
            base_score = min(impact + exploitability, 10.0)
            
        # Round up to 1 decimal
        base_score = round(base_score * 10) / 10
        
        # Determine severity
        if base_score == 0.0:
            severity = "None"
        elif base_score <= 3.9:
            severity = "Low"
        elif base_score <= 6.9:
            severity = "Medium"
        elif base_score <= 8.9:
            severity = "High"
        else:
            severity = "Critical"
            
        # Build vector string
        vector = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
        
        return {
            "score": base_score,
            "severity": severity,
            "vector": vector,
            "exploitability": round(exploitability, 2),
            "impact": round(impact, 2) if impact > 0 else 0
        }
        
    def get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            "None": "#53aa33",
            "Low": "#ffcb0d",
            "Medium": "#f9a009",
            "High": "#df3d03",
            "Critical": "#cc0500"
        }
        return colors.get(severity, "#808080")


# Pre-defined CVSS scores for common vulnerabilities
VULNERABILITY_CVSS = {
    "sql_injection": {
        "vector": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N", 
                  "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "H", "availability": "H"},
        "typical_score": 9.8
    },
    "xss_reflected": {
        "vector": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                  "user_interaction": "R", "scope": "C", "confidentiality": "L", "integrity": "L", "availability": "N"},
        "typical_score": 6.1
    },
    "xss_stored": {
        "vector": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "L",
                  "user_interaction": "R", "scope": "C", "confidentiality": "L", "integrity": "L", "availability": "N"},
        "typical_score": 5.4
    },
    "command_injection": {
        "vector": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                  "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "H", "availability": "H"},
        "typical_score": 9.8
    },
    "path_traversal": {
        "vector": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                  "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "N", "availability": "N"},
        "typical_score": 7.5
    },
    "ssrf": {
        "vector": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                  "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "L", "availability": "N"},
        "typical_score": 8.6
    },
    "idor": {
        "vector": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "L",
                  "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "H", "availability": "N"},
        "typical_score": 8.1
    },
    "xxe": {
        "vector": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                  "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "N", "availability": "L"},
        "typical_score": 8.2
    },
    "csrf": {
        "vector": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                  "user_interaction": "R", "scope": "U", "confidentiality": "N", "integrity": "H", "availability": "N"},
        "typical_score": 6.5
    },
    "missing_security_headers": {
        "vector": {"attack_vector": "N", "attack_complexity": "H", "privileges_required": "N",
                  "user_interaction": "R", "scope": "U", "confidentiality": "L", "integrity": "L", "availability": "N"},
        "typical_score": 4.2
    },
    "insecure_cookie": {
        "vector": {"attack_vector": "N", "attack_complexity": "H", "privileges_required": "N",
                  "user_interaction": "R", "scope": "U", "confidentiality": "L", "integrity": "N", "availability": "N"},
        "typical_score": 3.1
    },
    "default_credentials": {
        "vector": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                  "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "H", "availability": "H"},
        "typical_score": 9.8
    },
    "outdated_component": {
        "vector": {"attack_vector": "N", "attack_complexity": "H", "privileges_required": "N",
                  "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "H", "availability": "H"},
        "typical_score": 8.1
    },
    "insecure_deserialization": {
        "vector": {"attack_vector": "N", "attack_complexity": "L", "privileges_required": "N",
                  "user_interaction": "N", "scope": "U", "confidentiality": "H", "integrity": "H", "availability": "H"},
        "typical_score": 9.8
    },
}


def get_cvss_for_vulnerability(vuln_type: str) -> Dict[str, Any]:
    """Get pre-calculated CVSS data for a vulnerability type"""
    if vuln_type in VULNERABILITY_CVSS:
        calc = CVSSCalculator()
        data = VULNERABILITY_CVSS[vuln_type]
        result = calc.calculate_base_score(**data["vector"])
        return result
    else:
        return {
            "score": 5.0,
            "severity": "Medium",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            "exploitability": 3.9,
            "impact": 2.5
        }
