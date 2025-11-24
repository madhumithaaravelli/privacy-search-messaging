"""
Network Traffic Logger for Privacy Analysis
Captures HTTP requests/responses to analyze what information leaves the device
"""

import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class TrafficLogger:
    """Logs network traffic for privacy analysis"""
    
    def __init__(self, log_file: str = "traffic_log.jsonl"):
        """
        Initialize traffic logger
        
        Args:
            log_file: Path to JSONL file where logs will be written
        """
        self.log_file = log_file
        self.logs: List[Dict[str, Any]] = []
        self.session_id = None
        
    def start_session(self, session_name: str = None):
        """Start a new logging session"""
        self.session_id = f"{datetime.now().isoformat()}_{session_name or 'session'}"
        
    def log_request(self, 
                   method: str,
                   url: str,
                   headers: Dict[str, str] = None,
                   params: Dict[str, Any] = None,
                   data: Any = None,
                   query_type: str = None,
                   query_text: str = None) -> Dict[str, Any]:
        """
        Log an outgoing HTTP request
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            headers: Request headers
            params: Query parameters
            data: Request body/data
            query_type: Type of query (e.g., "search", "llm", "image")
            query_text: The actual query text if applicable
            
        Returns:
            Log entry dictionary
        """
        parsed_url = urlparse(url)
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "type": "request",
            "method": method,
            "url": url,
            "domain": parsed_url.netloc,
            "path": parsed_url.path,
            "scheme": parsed_url.scheme,
            "headers": dict(headers) if headers else {},
            "params": dict(params) if params else {},
            "query_type": query_type,
            "query_text": query_text,
            "data_size": len(str(data)) if data else 0,
            "params_size": len(str(params)) if params else 0,  # Size of URL parameters
            "is_localhost": parsed_url.hostname in ["localhost", "127.0.0.1", "::1"]
        }
        
        # Redact sensitive data from headers (keep structure, remove values)
        if headers:
            log_entry["headers_redacted"] = {
                k: "[REDACTED]" if any(sensitive in k.lower() for sensitive in 
                    ["authorization", "cookie", "token", "api-key", "secret"]) 
                else v 
                for k, v in headers.items()
            }
        
        self.logs.append(log_entry)
        self._write_log(log_entry)
        
        return log_entry
    
    def log_response(self,
                    request_log: Dict[str, Any],
                    status_code: int,
                    headers: Dict[str, str] = None,
                    response_size: int = 0,
                    response_time: float = 0) -> Dict[str, Any]:
        """
        Log an HTTP response
        
        Args:
            request_log: The corresponding request log entry
            status_code: HTTP status code
            headers: Response headers
            response_size: Size of response body in bytes
            response_time: Time taken for request in seconds
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "session_id": self.session_id,
            "type": "response",
            "request_id": len(self.logs) - 1,  # Reference to request
            "status_code": status_code,
            "headers": dict(headers) if headers else {},
            "response_size": response_size,
            "response_time": response_time,
            "url": request_log.get("url"),
            "domain": request_log.get("domain")
        }
        
        self.logs.append(log_entry)
        self._write_log(log_entry)
        
        return log_entry
    
    def _write_log(self, log_entry: Dict[str, Any]):
        """Write log entry to file (JSONL format)"""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"Warning: Failed to write traffic log: {e}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of logged traffic"""
        if not self.logs:
            return {}
        
        requests = [log for log in self.logs if log.get("type") == "request"]
        responses = [log for log in self.logs if log.get("type") == "response"]
        
        domains = {}
        localhost_count = 0
        external_count = 0
        
        for req in requests:
            domain = req.get("domain", "unknown")
            if domain not in domains:
                domains[domain] = {"count": 0, "is_localhost": req.get("is_localhost", False)}
            domains[domain]["count"] += 1
            
            if req.get("is_localhost"):
                localhost_count += 1
            else:
                external_count += 1
        
        return {
            "total_requests": len(requests),
            "total_responses": len(responses),
            "localhost_requests": localhost_count,
            "external_requests": external_count,
            "unique_domains": len(domains),
            "domains": domains,
            "session_id": self.session_id
        }
    
    def export_summary(self, output_file: str = "traffic_summary.json"):
        """Export summary to JSON file"""
        summary = self.get_summary()
        summary["all_logs"] = self.logs
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        return summary


class LoggingHTTPAdapter(HTTPAdapter):
    """HTTPAdapter that logs all requests/responses"""
    
    def __init__(self, traffic_logger: TrafficLogger, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.traffic_logger = traffic_logger
    
    def send(self, request, **kwargs):
        """Override send to log request/response"""
        start_time = time.time()
        
        # Log request
        request_log = self.traffic_logger.log_request(
            method=request.method,
            url=request.url,
            headers=dict(request.headers),
            params=dict(request.params) if hasattr(request, 'params') else None,
            data=request.body if hasattr(request, 'body') else None
        )
        
        # Make request
        response = super().send(request, **kwargs)
        
        # Log response
        response_time = time.time() - start_time
        self.traffic_logger.log_response(
            request_log=request_log,
            status_code=response.status_code,
            headers=dict(response.headers),
            response_size=len(response.content) if hasattr(response, 'content') else 0,
            response_time=response_time
        )
        
        return response


def create_logging_session(log_file: str = "traffic_log.jsonl") -> requests.Session:
    """
    Create a requests Session with traffic logging enabled
    
    Args:
        log_file: Path to log file
        
    Returns:
        requests.Session with logging adapter
    """
    logger = TrafficLogger(log_file)
    logger.start_session()
    
    session = requests.Session()
    adapter = LoggingHTTPAdapter(logger)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    
    # Store logger in session for access
    session.traffic_logger = logger
    
    return session

