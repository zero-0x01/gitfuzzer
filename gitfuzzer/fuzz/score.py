"""Risk scoring model for GitFuzzer.

This module calculates risk scores based on found secrets,
live endpoints, and organization context.
"""

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional
import aiohttp

from .secret_rules import SecretMatch
from .endpoint_extractor import EndpointMatch
from .org_infer import OrganizationInfo


class RiskLevel(Enum):
    """Risk level enumeration."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskAssessment:
    """Complete risk assessment for a repository."""
    total_score: int
    risk_level: RiskLevel
    secret_score: int
    endpoint_score: int
    organization_score: int
    factors: List[str]
    recommendations: List[str]


class RiskScorer:
    """Calculates risk scores for repository findings."""
    
    def __init__(self, config: Optional[Dict] = None):
        """Initialize risk scorer.
        
        Args:
            config: Scoring configuration
        """
        self.config = config or {}
        
        # Default scoring weights
        self.secret_weights = {
            # High-risk secrets
            'aws-access-key-id': 50,
            'aws-secret-access-key': 50,
            'github-pat': 45,
            'google-api-key': 40,
            'private-key': 50,
            'ssh-private-key': 50,
            'jwt-token': 35,
            
            # Medium-risk secrets
            'slack-token': 30,
            'discord-bot-token': 30,
            'telegram-bot-token': 30,
            'stripe-secret': 40,
            'twilio-auth-token': 35,
            'sendgrid-api-key': 30,
            
            # Lower-risk but notable
            'generic-api-key': 20,
            'bearer-token': 25,
            'high-entropy-base64': 15,
            'high-entropy-hex': 15,
            'password-in-url': 30,
        }
        
        # Risk level thresholds
        self.thresholds = {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 30,
            RiskLevel.HIGH: 70,
            RiskLevel.CRITICAL: 100
        }
        
        # Override with config if provided
        if 'secret_weights' in self.config:
            self.secret_weights.update(self.config['secret_weights'])
        if 'thresholds' in self.config:
            self.thresholds.update(self.config['thresholds'])
    
    def assess_risk(self,
                   secret_matches: List[SecretMatch],
                   endpoint_matches: List[EndpointMatch],
                   organization: Optional[OrganizationInfo]) -> RiskAssessment:
        """Assess overall risk for repository findings.
        
        Args:
            secret_matches: Found secrets
            endpoint_matches: Found endpoints
            organization: Inferred organization
            
        Returns:
            Complete risk assessment
        """
        # Calculate component scores
        secret_score = self._score_secrets(secret_matches)
        endpoint_score = self._score_endpoints(endpoint_matches)
        org_score = self._score_organization(organization, endpoint_matches)
        
        # Calculate total score
        total_score = secret_score + endpoint_score + org_score
        
        # Determine risk level
        risk_level = self._determine_risk_level(total_score)
        
        # Generate factors and recommendations
        factors = self._generate_risk_factors(secret_matches, endpoint_matches, organization)
        recommendations = self._generate_recommendations(secret_matches, endpoint_matches, organization, risk_level)
        
        return RiskAssessment(
            total_score=total_score,
            risk_level=risk_level,
            secret_score=secret_score,
            endpoint_score=endpoint_score,
            organization_score=org_score,
            factors=factors,
            recommendations=recommendations
        )
    
    def _score_secrets(self, secret_matches: List[SecretMatch]) -> int:
        """Calculate score based on found secrets.
        
        Args:
            secret_matches: List of secret matches
            
        Returns:
            Secret risk score
        """
        if not secret_matches:
            return 0
        
        total_score = 0
        high_entropy_count = 0
        
        for match in secret_matches:
            # Base score from rule type
            base_score = self.secret_weights.get(match.rule_id, 10)
            
            # Adjust based on confidence
            confidence_multiplier = match.confidence
            
            # Adjust based on entropy for generic rules
            if match.rule_id in ['high-entropy-base64', 'high-entropy-hex']:
                high_entropy_count += 1
                if match.entropy > 5.0:
                    confidence_multiplier += 0.2
                elif match.entropy < 4.0:
                    confidence_multiplier -= 0.3
            
            # Calculate final score for this secret
            secret_score = int(base_score * confidence_multiplier)
            total_score += secret_score
        
        # Bonus for multiple high-entropy keys
        if high_entropy_count > 1:
            total_score += min(5 * (high_entropy_count - 1), 20)
        
        return min(total_score, 80)  # Cap at 80 points for secrets
    
    def _score_endpoints(self, endpoint_matches: List[EndpointMatch]) -> int:
        """Calculate score based on discovered endpoints.
        
        Args:
            endpoint_matches: List of endpoint matches
            
        Returns:
            Endpoint risk score
        """
        if not endpoint_matches:
            return 0
        
        score = 0
        live_ips = []
        live_urls = []
        
        for match in endpoint_matches:
            if not match.is_live:
                continue
            
            if match.endpoint_type == 'ip':
                live_ips.append(match)
            elif match.endpoint_type == 'url':
                live_urls.append(match)
                
                # Score based on status code
                if match.status_code == 200:
                    score += 15
                elif match.status_code in [201, 202, 204]:
                    score += 12
                elif match.status_code in [301, 302, 307, 308]:
                    score += 8
                elif match.status_code in [401, 403]:
                    score += 10  # Protected resource
                elif match.status_code == 404:
                    score += 2   # Endpoint exists but resource not found
        
        # Bonus for live IPs with open ports
        if live_ips:
            score += min(20, len(live_ips) * 5)
        
        # Bonus for API endpoints
        api_endpoints = [ep for ep in live_urls if 'api' in ep.url.lower()]
        if api_endpoints:
            score += min(15, len(api_endpoints) * 3)
        
        return min(score, 50)  # Cap at 50 points for endpoints
    
    def _score_organization(self, 
                           organization: Optional[OrganizationInfo],
                           endpoint_matches: List[EndpointMatch]) -> int:
        """Calculate score based on organization context.
        
        Args:
            organization: Inferred organization
            endpoint_matches: Endpoint matches for context
            
        Returns:
            Organization risk score
        """
        if not organization:
            return 0
        
        score = 0
        
        # Base score for identified organization
        if organization.confidence > 0.8:
            score += 10
        elif organization.confidence > 0.6:
            score += 5
        
        # Check for high-value domains
        high_value_indicators = [
            'bank', 'financial', 'payment', 'crypto', 'bitcoin',
            'government', 'military', 'defense', 'healthcare',
            'university', 'education', 'research'
        ]
        
        org_name_lower = organization.name.lower()
        for indicator in high_value_indicators:
            if indicator in org_name_lower:
                score += 15
                break
        
        # Check domains for sensitive contexts
        for domain in organization.domains:
            domain_lower = domain.lower()
            for indicator in high_value_indicators:
                if indicator in domain_lower:
                    score += 10
                    break
        
        # Check for freshly registered domains (would need WHOIS lookup)
        # This is a placeholder - in production you'd implement WHOIS checking
        
        return min(score, 30)  # Cap at 30 points for organization
    
    def _determine_risk_level(self, total_score: int) -> RiskLevel:
        """Determine risk level from total score.
        
        Args:
            total_score: Total calculated score
            
        Returns:
            Risk level
        """
        if total_score >= self.thresholds[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif total_score >= self.thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif total_score >= self.thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _generate_risk_factors(self,
                              secret_matches: List[SecretMatch],
                              endpoint_matches: List[EndpointMatch],
                              organization: Optional[OrganizationInfo]) -> List[str]:
        """Generate list of risk factors found.
        
        Args:
            secret_matches: Found secrets
            endpoint_matches: Found endpoints
            organization: Inferred organization
            
        Returns:
            List of risk factor descriptions
        """
        factors = []
        
        if secret_matches:
            high_risk_secrets = [s for s in secret_matches if self.secret_weights.get(s.rule_id, 0) >= 40]
            if high_risk_secrets:
                factors.append(f"{len(high_risk_secrets)} high-risk secrets found")
            
            total_secrets = len(secret_matches)
            if total_secrets > 1:
                factors.append(f"{total_secrets} total secrets detected")
        
        live_endpoints = [ep for ep in endpoint_matches if ep.is_live]
        if live_endpoints:
            factors.append(f"{len(live_endpoints)} live endpoints discovered")
        
        live_ips = [ep for ep in live_endpoints if ep.endpoint_type == 'ip']
        if live_ips:
            factors.append(f"{len(live_ips)} live IP addresses with open ports")
        
        api_endpoints = [ep for ep in live_endpoints if 'api' in ep.url.lower()]
        if api_endpoints:
            factors.append(f"{len(api_endpoints)} live API endpoints")
        
        if organization and organization.confidence > 0.6:
            factors.append(f"Associated with {organization.name}")
        
        # Check for sensitive content indicators
        sensitive_patterns = ['password', 'token', 'key', 'secret', 'auth']
        sensitive_files = []
        for match in secret_matches:
            file_lower = match.file_path.lower()
            if any(pattern in file_lower for pattern in sensitive_patterns):
                sensitive_files.append(match.file_path)
        
        if sensitive_files:
            factors.append(f"Secrets found in {len(set(sensitive_files))} sensitive files")
        
        return factors
    
    def _generate_recommendations(self,
                                 secret_matches: List[SecretMatch],
                                 endpoint_matches: List[EndpointMatch],
                                 organization: Optional[OrganizationInfo],
                                 risk_level: RiskLevel) -> List[str]:
        """Generate security recommendations.
        
        Args:
            secret_matches: Found secrets
            endpoint_matches: Found endpoints
            organization: Inferred organization
            risk_level: Calculated risk level
            
        Returns:
            List of security recommendations
        """
        recommendations = []
        
        if secret_matches:
            recommendations.append("Immediately rotate all exposed secrets and API keys")
            recommendations.append("Implement secret scanning in CI/CD pipeline")
            recommendations.append("Use environment variables or secret management systems")
        
        aws_secrets = [s for s in secret_matches if s.rule_id.startswith('aws-')]
        if aws_secrets:
            recommendations.append("Review AWS IAM permissions and rotate AWS credentials")
            recommendations.append("Enable AWS CloudTrail to monitor API usage")
        
        github_secrets = [s for s in secret_matches if s.rule_id.startswith('github-')]
        if github_secrets:
            recommendations.append("Rotate GitHub personal access tokens")
            recommendations.append("Review GitHub repository access permissions")
        
        live_endpoints = [ep for ep in endpoint_matches if ep.is_live]
        if live_endpoints:
            recommendations.append("Audit exposed endpoints for sensitive data")
            recommendations.append("Implement proper authentication and rate limiting")
        
        live_ips = [ep for ep in live_endpoints if ep.endpoint_type == 'ip']
        if live_ips:
            recommendations.append("Review firewall rules for exposed IP addresses")
            recommendations.append("Consider using VPN or private networking")
        
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            recommendations.append("Consider this a security incident requiring immediate attention")
            recommendations.append("Conduct thorough security audit of the entire system")
            recommendations.append("Implement additional monitoring and alerting")
        
        if organization and organization.confidence > 0.6:
            recommendations.append(f"Notify {organization.name} security team if this is unauthorized exposure")
        
        # Generic recommendations
        recommendations.extend([
            "Remove secrets from version control history",
            "Implement branch protection rules",
            "Enable security scanning tools",
            "Educate developers on secure coding practices"
        ])
        
        return recommendations
