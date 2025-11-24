"""
Privacy Analyzer - Analyzes traffic logs and generates privacy labels
"""

import json
import sys
from typing import Dict, List, Any
from collections import defaultdict
from datetime import datetime


class PrivacyAnalyzer:
    """Analyzes network traffic logs for privacy implications"""
    
    def __init__(self, log_file: str):
        """
        Initialize analyzer with traffic log
        
        Args:
            log_file: Path to JSONL traffic log file or JSON summary file
        """
        self.log_file = log_file
        self.logs = []
        self._load_logs()
    
    def _load_logs(self):
        """Load logs from file"""
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                # Try JSON first (summary file)
                try:
                    data = json.load(f)
                    if "all_logs" in data:
                        self.logs = data["all_logs"]
                    else:
                        self.logs = data.get("logs", [])
                except json.JSONDecodeError:
                    # Try JSONL format
                    f.seek(0)
                    self.logs = [json.loads(line) for line in f if line.strip()]
        except FileNotFoundError:
            print(f"Error: Log file not found: {self.log_file}")
            sys.exit(1)
    
    def analyze_traffic(self) -> Dict[str, Any]:
        """Analyze traffic and extract privacy-relevant information"""
        requests = [log for log in self.logs if log.get("type") == "request"]
        
        analysis = {
            "total_requests": len(requests),
            "domains_contacted": defaultdict(int),
            "localhost_only": True,
            "external_domains": [],
            "query_data_leaked": [],
            "headers_analysis": defaultdict(list),
            "metadata_exposure": [],
            "api_keys_exposed": [],
            "ip_address_exposure": False,
            "timing_patterns": [],
            "session_tracking": []
        }
        
        for req in requests:
            domain = req.get("domain", "unknown")
            analysis["domains_contacted"][domain] += 1
            
            # Check if localhost
            if req.get("is_localhost"):
                continue
            else:
                analysis["localhost_only"] = False
                analysis["ip_address_exposure"] = True  # IP is exposed when contacting external domains
                if domain not in analysis["external_domains"]:
                    analysis["external_domains"].append(domain)
            
            # Analyze query text exposure
            if req.get("query_text"):
                analysis["query_data_leaked"].append({
                    "domain": domain,
                    "query": req.get("query_text"),
                    "url": req.get("url")
                })
            
            # Analyze headers for metadata leakage
            headers = req.get("headers", {})
            for header_name, header_value in headers.items():
                header_lower = header_name.lower()
                # Check for fingerprinting headers
                if any(sensitive in header_lower for sensitive in 
                       ["user-agent", "referer", "cookie", "accept", "accept-language", 
                        "accept-encoding", "dnt", "connection", "upgrade-insecure-requests"]):
                    analysis["headers_analysis"][header_name].append({
                        "domain": domain,
                        "value": header_value[:50] + "..." if len(str(header_value)) > 50 else header_value,
                        "privacy_risk": self._assess_header_risk(header_name, header_value)
                    })
            
            # Check for metadata in URL params
            params = req.get("params", {})
            if params:
                param_metadata = {
                    "domain": domain,
                    "params": {},
                    "sensitive_params": []
                }
                
                # Check for API keys, tokens, session IDs in params
                for param_name, param_value in params.items():
                    param_lower = param_name.lower()
                    param_metadata["params"][param_name] = param_value
                    
                    # Detect sensitive parameters
                    if any(keyword in param_lower for keyword in 
                           ["key", "token", "api", "secret", "auth", "session", "id", "uid"]):
                        if param_lower in ["key", "api_key", "apikey"]:
                            analysis["api_keys_exposed"].append({
                                "domain": domain,
                                "param": param_name,
                                "exposed": True
                            })
                        param_metadata["sensitive_params"].append(param_name)
                
                analysis["metadata_exposure"].append(param_metadata)
            
            # Analyze timing patterns (for correlation attacks)
            timestamp = req.get("timestamp")
            if timestamp:
                analysis["timing_patterns"].append({
                    "domain": domain,
                    "timestamp": timestamp
                })
            
            # Check for session tracking
            session_id = req.get("session_id")
            if session_id and not req.get("is_localhost"):
                analysis["session_tracking"].append({
                    "domain": domain,
                    "session_id": session_id[:20] + "..." if len(session_id) > 20 else session_id
                })
        
        return analysis
    
    def _assess_header_risk(self, header_name: str, header_value: str) -> str:
        """Assess privacy risk level of a header"""
        header_lower = header_name.lower()
        
        if "user-agent" in header_lower:
            return "HIGH - Browser fingerprinting"
        elif "cookie" in header_lower:
            return "HIGH - Tracking cookies"
        elif "referer" in header_lower:
            return "MEDIUM - Referrer leakage"
        elif "accept-language" in header_lower:
            return "MEDIUM - Language/location inference"
        elif "accept" in header_lower:
            return "LOW - Content negotiation"
        else:
            return "LOW - Standard header"
    
    def generate_privacy_label(self) -> Dict[str, Any]:
        """
        Generate privacy label based on analysis
        Format: What data exits device, Who has access, Retention policy
        """
        analysis = self.analyze_traffic()
        
        label = {
            "system": "Unknown",
            "data_exits_device": [],
            "who_has_access": [],
            "retention_policy": "Unknown",
            "privacy_score": 0,  # 0-100, higher = more private
            "recommendations": []
        }
        
        # Determine system type
        if analysis["localhost_only"]:
            label["system"] = "Local/Self-Hosted"
            label["data_exits_device"] = ["None - all traffic stays local"]
            label["who_has_access"] = ["Only local system"]
            label["retention_policy"] = "No external retention"
            label["privacy_score"] = 100
            label["recommendations"] = ["Excellent privacy - no data leaves device"]
        else:
            label["system"] = "Cloud/External"
            label["data_exits_device"] = []
            
            # Query data
            if analysis["query_data_leaked"]:
                unique_queries = len(set(q["query"] for q in analysis["query_data_leaked"]))
                label["data_exits_device"].append(
                    f"Search queries ({unique_queries} unique queries)"
                )
            
            # Headers
            if analysis["headers_analysis"]:
                header_types = list(analysis["headers_analysis"].keys())
                label["data_exits_device"].append(f"HTTP headers: {', '.join(header_types)}")
            
            # Metadata
            if analysis["metadata_exposure"]:
                sensitive_count = sum(len(m.get("sensitive_params", [])) for m in analysis["metadata_exposure"])
                label["data_exits_device"].append(
                    f"URL parameters and metadata ({sensitive_count} sensitive parameters)"
                )
            
            # API keys/tokens
            if analysis["api_keys_exposed"]:
                label["data_exits_device"].append(
                    f"API keys/tokens ({len(analysis['api_keys_exposed'])} exposed)"
                )
            
            # IP address exposure
            if analysis["ip_address_exposure"]:
                label["data_exits_device"].append("IP address (implicit via external connection)")
            
            # Headers (metadata leakage)
            if analysis["headers_analysis"]:
                high_risk_headers = [
                    h for h, values in analysis["headers_analysis"].items()
                    if any(v.get("privacy_risk", "").startswith("HIGH") for v in values)
                ]
                if high_risk_headers:
                    label["data_exits_device"].append(
                        f"Browser fingerprinting headers: {', '.join(high_risk_headers)}"
                    )
            
            # Timing patterns
            if len(analysis["timing_patterns"]) > 10:
                label["data_exits_device"].append(
                    f"Timing patterns ({len(analysis['timing_patterns'])} requests) - correlation possible"
                )
            
            # Who has access
            for domain in analysis["external_domains"]:
                label["who_has_access"].append(domain)
            
            # Retention policy (generic - would need actual policy docs)
            label["retention_policy"] = "Unknown - check provider privacy policy"
            
            # Privacy score calculation (enhanced for metadata leakage)
            score = 100
            score -= len(analysis["external_domains"]) * 10  # External domains
            score -= len(analysis["query_data_leaked"]) * 5  # Query exposure
            score -= len(analysis["api_keys_exposed"]) * 15  # API key exposure (severe)
            score -= len(analysis["headers_analysis"]) * 3  # Header metadata
            # High-risk headers (fingerprinting)
            high_risk_count = sum(
                1 for values in analysis["headers_analysis"].values()
                for v in values if v.get("privacy_risk", "").startswith("HIGH")
            )
            score -= high_risk_count * 5  # High-risk headers
            # IP exposure
            if analysis["ip_address_exposure"]:
                score -= 5
            # Timing correlation risk
            if len(analysis["timing_patterns"]) > 20:
                score -= 3
            label["privacy_score"] = max(0, score)
            
            # Recommendations
            if label["privacy_score"] < 50:
                label["recommendations"].append("Consider using local/self-hosted alternatives")
            if analysis["query_data_leaked"]:
                label["recommendations"].append("Queries are being sent to external servers")
            if analysis["api_keys_exposed"]:
                label["recommendations"].append(
                    f"WARNING: {len(analysis['api_keys_exposed'])} API keys/tokens exposed in requests"
                )
            if analysis["ip_address_exposure"]:
                label["recommendations"].append("IP address exposed to external servers")
            if high_risk_count > 0:
                label["recommendations"].append(
                    f"Browser fingerprinting detected via {high_risk_count} high-risk headers"
                )
            if len(analysis["external_domains"]) > 3:
                label["recommendations"].append("Multiple external services contacted")
        
        return label
    
    def compare_with_cloud(self, cloud_log_file: str) -> Dict[str, Any]:
        """
        Compare local system with cloud system
        
        Args:
            cloud_log_file: Path to cloud system's traffic log
        """
        local_analysis = self.analyze_traffic()
        local_label = self.generate_privacy_label()
        
        cloud_analyzer = PrivacyAnalyzer(cloud_log_file)
        cloud_analysis = cloud_analyzer.analyze_traffic()
        cloud_label = cloud_analyzer.generate_privacy_label()
        
        comparison = {
            "comparison_date": datetime.now().isoformat(),
            "local_system": {
                "analysis": local_analysis,
                "privacy_label": local_label
            },
            "cloud_system": {
                "analysis": cloud_analysis,
                "privacy_label": cloud_label
            },
            "key_differences": {
                "external_domains": {
                    "local": len(local_analysis["external_domains"]),
                    "cloud": len(cloud_analysis["external_domains"])
                },
                "query_exposure": {
                    "local": len(local_analysis["query_data_leaked"]),
                    "cloud": len(cloud_analysis["query_data_leaked"])
                },
                "privacy_score": {
                    "local": local_label["privacy_score"],
                    "cloud": cloud_label["privacy_score"]
                }
            }
        }
        
        return comparison
    
    def export_report(self, output_file: str = None):
        """Export full privacy analysis report"""
        if output_file is None:
            output_file = f"privacy_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            "analysis_date": datetime.now().isoformat(),
            "log_file": self.log_file,
            "traffic_analysis": self.analyze_traffic(),
            "privacy_label": self.generate_privacy_label()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"Privacy report exported to: {output_file}")
        return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python privacy_analyzer.py <traffic_log_file> [output_file]")
        print("Example: python privacy_analyzer.py traffic_log_local.jsonl")
        sys.exit(1)
    
    log_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    analyzer = PrivacyAnalyzer(log_file)
    report = analyzer.export_report(output_file)
    
    # Print summary
    label = report["privacy_label"]
    print("\n" + "=" * 60)
    print("PRIVACY LABEL SUMMARY")
    print("=" * 60)
    print(f"System: {label['system']}")
    print(f"Privacy Score: {label['privacy_score']}/100")
    print(f"\nData that exits device:")
    for item in label["data_exits_device"]:
        print(f"  - {item}")
    print(f"\nWho has access:")
    for item in label["who_has_access"]:
        print(f"  - {item}")
    print(f"\nRetention Policy: {label['retention_policy']}")
    if label["recommendations"]:
        print(f"\nRecommendations:")
        for rec in label["recommendations"]:
            print(f"  - {rec}")

