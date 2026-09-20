"""
Data models and Enums for AI-driven device security profiling and risk assessment.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List


class NetworkPosture(str, Enum):
    """Overall LAN security posture classification."""
    SECURE = "SECURE"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        return self.value


class RiskLevel(str, Enum):
    """Device security risk evaluation tier."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __str__(self) -> str:
        return self.value


class WhitelistRecommendation(str, Enum):
    """Recommended administrator action for device access."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    INVESTIGATE = "INVESTIGATE"

    def __str__(self) -> str:
        return self.value


@dataclass
class DeviceRiskAssessment:
    """Encapsulates an AI-generated security profile for a network device."""
    device_type: str
    risk_level: RiskLevel
    summary: str
    whitelist_recommendation: WhitelistRecommendation
    action_advice: str
    provider: str = "Unknown"
    confidence: str = "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_type": self.device_type,
            "risk_level": str(self.risk_level.value if hasattr(self.risk_level, "value") else self.risk_level),
            "summary": self.summary,
            "whitelist_recommendation": str(
                self.whitelist_recommendation.value
                if hasattr(self.whitelist_recommendation, "value")
                else self.whitelist_recommendation
            ),
            "action_advice": self.action_advice,
            "provider": self.provider,
            "confidence": self.confidence,
        }


@dataclass
class NetworkPostureAssessment:
    """Encapsulates a deterministic security posture with AI-synthesized executive commentary."""
    posture: NetworkPosture
    summary: str
    threats_found: List[str] = field(default_factory=list)
    hardening_advice: List[str] = field(default_factory=list)
    provider: str = "Unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "posture": str(self.posture.value if hasattr(self.posture, "value") else self.posture),
            "summary": self.summary,
            "threats_found": self.threats_found,
            "hardening_advice": self.hardening_advice,
            "provider": self.provider,
        }
