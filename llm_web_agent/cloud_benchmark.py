"""
Cloud Benchmark Script
Runs the same queries on cloud services (Google Search, OpenAI, etc.) and logs traffic
"""

import sys
import time
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from traffic_logger import TrafficLogger
import requests
import config


# Import the same queries from benchmark.py
try:
    from benchmark import BENCHMARK_QUERIES
except ImportError:
    # Fallback if can't import
    BENCHMARK_QUERIES = []


class CloudBenchmark:
    """Base class for cloud service benchmarks"""
    
    def __init__(self, service_name: str, logger: TrafficLogger):
        self.service_name = service_name
        self.logger = logger
    
    def run_query(self, query: str) -> Dict[str, Any]:
        """Run a single query - to be implemented by subclasses"""
        raise NotImplementedError


class GoogleSearchBenchmark(CloudBenchmark):
    """Benchmark using Google Custom Search API"""
    
    def __init__(self, api_key: str, search_engine_id: str, logger: TrafficLogger):
        super().__init__("google_search", logger)
        self.api_key = api_key
        self.search_engine_id = search_engine_id
        self.base_url = "https://www.googleapis.com/customsearch/v1"
    
    def run_query(self, query: str) -> Dict[str, Any]:
        """Run query on Google Custom Search API"""
        start_time = time.time()
        result = {
            "query": query,
            "system": "google_search",
            "start_time": datetime.now().isoformat(),
            "success": False,
            "error": None,
            "response": None,
            "response_time": 0
        }
        
        try:
            params = {
                "key": self.api_key,
                "cx": self.search_engine_id,
                "q": query,
                "num": 5  # Number of results
            }
            
            # Log request
            self.logger.log_request(
                method="GET",
                url=self.base_url,
                params=params,
                query_type="search",
                query_text=query
            )
            
            response = requests.get(self.base_url, params=params, timeout=30)
            response_time = time.time() - start_time
            
            # Log response
            self.logger.log_response(
                request_log={"url": self.base_url, "domain": "www.googleapis.com"},
                status_code=response.status_code,
                response_size=len(response.content),
                response_time=response_time
            )
            
            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])
                result["response"] = "\n".join([
                    f"{i+1}. {item.get('title', '')}: {item.get('snippet', '')}"
                    for i, item in enumerate(items[:5])
                ])
                result["success"] = True
            else:
                result["error"] = f"HTTP {response.status_code}: {response.text[:200]}"
            
            result["response_time"] = response_time
            
        except Exception as e:
            result["error"] = str(e)
            result["response_time"] = time.time() - start_time
        
        result["end_time"] = datetime.now().isoformat()
        return result


class OpenAIBenchmark(CloudBenchmark):
    """Benchmark using OpenAI API (ChatGPT)"""
    
    def __init__(self, api_key: str, model: str = "gpt-3.5-turbo", logger: TrafficLogger = None):
        super().__init__("openai", logger)
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.openai.com/v1/chat/completions"
    
    def run_query(self, query: str) -> Dict[str, Any]:
        """Run query on OpenAI API"""
        start_time = time.time()
        result = {
            "query": query,
            "system": "openai",
            "start_time": datetime.now().isoformat(),
            "success": False,
            "error": None,
            "response": None,
            "response_time": 0
        }
        
        try:
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": query}
                ],
                "max_tokens": 1000,
                "temperature": 0.7
            }
            
            # Log request (redact API key)
            self.logger.log_request(
                method="POST",
                url=self.base_url,
                headers={k: "[REDACTED]" if "authorization" in k.lower() else v 
                       for k, v in headers.items()},
                data=json.dumps(payload),
                query_type="llm",
                query_text=query
            )
            
            response = requests.post(
                self.base_url,
                headers=headers,
                json=payload,
                timeout=60
            )
            response_time = time.time() - start_time
            
            # Log response
            self.logger.log_response(
                request_log={"url": self.base_url, "domain": "api.openai.com"},
                status_code=response.status_code,
                response_size=len(response.content),
                response_time=response_time
            )
            
            if response.status_code == 200:
                data = response.json()
                result["response"] = data["choices"][0]["message"]["content"]
                result["success"] = True
            else:
                result["error"] = f"HTTP {response.status_code}: {response.text[:200]}"
            
            result["response_time"] = response_time
            
        except Exception as e:
            result["error"] = str(e)
            result["response_time"] = time.time() - start_time
        
        result["end_time"] = datetime.now().isoformat()
        return result


class ChatGPTWebBenchmark(CloudBenchmark):
    """
    Benchmark using ChatGPT Web (requires browser automation)
    Note: This is more complex and may violate ToS. Use API instead if possible.
    """
    
    def __init__(self, logger: TrafficLogger):
        super().__init__("chatgpt_web", logger)
        print("WARNING: ChatGPT Web scraping may violate ToS.")
        print("Consider using OpenAI API instead (cloud_benchmark.py --openai)")
        print("For web version, use browser automation (Selenium/Playwright)")
        print("and capture traffic with Wireshark separately.")


def run_cloud_benchmark(
    service: str,
    queries: List[str] = None,
    api_key: str = None,
    **kwargs
) -> Dict[str, Any]:
    """
    Run benchmark on cloud service
    
    Args:
        service: 'google', 'openai', or 'chatgpt_web'
        queries: List of queries (defaults to BENCHMARK_QUERIES)
        api_key: API key for the service
        **kwargs: Additional service-specific parameters
    """
    if queries is None:
        queries = BENCHMARK_QUERIES
    
    # Create logger
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    logger = TrafficLogger(f"traffic_log_cloud_{service}_{timestamp}.jsonl")
    logger.start_session(f"cloud_benchmark_{service}")
    
    # Initialize benchmark
    if service == "google":
        if not api_key or not kwargs.get("search_engine_id"):
            print("ERROR: Google Search requires API key and search engine ID")
            print("Get them from: https://developers.google.com/custom-search")
            return None
        benchmark = GoogleSearchBenchmark(
            api_key, 
            kwargs["search_engine_id"], 
            logger
        )
    elif service == "openai":
        if not api_key:
            print("ERROR: OpenAI requires API key")
            print("Get it from: https://platform.openai.com/api-keys")
            return None
        benchmark = OpenAIBenchmark(
            api_key,
            kwargs.get("model", "gpt-3.5-turbo"),
            logger
        )
    else:
        print(f"ERROR: Unknown service: {service}")
        print("Available: 'google', 'openai'")
        return None
    
    print(f"Running {len(queries)} queries on {service}...")
    print("=" * 60)
    
    results = []
    for i, query in enumerate(queries, 1):
        print(f"\n[{i}/{len(queries)}] Query: {query}")
        result = benchmark.run_query(query)
        results.append(result)
        
        if result["success"]:
            print(f"  ✓ Success ({result['response_time']:.2f}s)")
            print(f"  Response: {result['response'][:100]}...")
        else:
            print(f"  ✗ Failed: {result.get('error', 'Unknown error')}")
        
        # Rate limiting - be nice to APIs
        if i < len(queries):
            time.sleep(1)  # 1 second between requests
    
    # Export results
    output_file = f"benchmark_results_cloud_{service}_{timestamp}.json"
    output_data = {
        "benchmark_date": datetime.now().isoformat(),
        "system": service,
        "queries": results,
        "traffic_summary": logger.get_summary()
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    
    # Export traffic summary
    logger.export_summary(f"traffic_summary_cloud_{service}_{timestamp}.json")
    
    print("\n" + "=" * 60)
    print("Benchmark complete!")
    print(f"Results saved to: {output_file}")
    print(f"Traffic summary: {logger.get_summary()}")
    
    return output_data


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python cloud_benchmark.py <service> [options]")
        print("\nServices:")
        print("  google    - Google Custom Search API")
        print("  openai    - OpenAI API (ChatGPT)")
        print("\nExamples:")
        print("  python cloud_benchmark.py google --api-key KEY --cx SEARCH_ENGINE_ID")
        print("  python cloud_benchmark.py openai --api-key KEY")
        print("\nEnvironment variables (alternative):")
        print("  GOOGLE_API_KEY, GOOGLE_CX")
        print("  OPENAI_API_KEY")
        sys.exit(1)
    
    service = sys.argv[1].lower()
    
    # Parse arguments
    api_key = None
    kwargs = {}
    
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--api-key" and i + 1 < len(sys.argv):
            api_key = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--cx" and i + 1 < len(sys.argv):
            kwargs["search_engine_id"] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--model" and i + 1 < len(sys.argv):
            kwargs["model"] = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--count" and i + 1 < len(sys.argv):
            count = int(sys.argv[i + 1])
            queries = BENCHMARK_QUERIES[:count] if count <= len(BENCHMARK_QUERIES) else BENCHMARK_QUERIES
            i += 2
        else:
            i += 1
    
    # Check environment variables if API key not provided
    if not api_key:
        if service == "google":
            api_key = os.getenv("GOOGLE_API_KEY")
            if not kwargs.get("search_engine_id"):
                kwargs["search_engine_id"] = os.getenv("GOOGLE_CX")
        elif service == "openai":
            api_key = os.getenv("OPENAI_API_KEY")
    
    # Use all queries if not specified
    if 'queries' not in locals():
        queries = None
    
    run_cloud_benchmark(service, queries, api_key, **kwargs)


