"""
Benchmark script for privacy analysis
Runs queries and logs network traffic for comparison
"""

import sys
import time
import json
from datetime import datetime
from typing import List, Dict, Any
from traffic_logger import TrafficLogger, create_logging_session
import requests
import config


# Default benchmark queries (50 queries covering various topics)
BENCHMARK_QUERIES = [
    # Weather and current events
    "What is the weather today?",
    "Current weather forecast",
    "What happened in the news today?",
    "Latest news about artificial intelligence",
    "Recent news about technology",
    "Today's top news stories",
    
    # Stock and finance
    "Current stock price of Apple",
    "Latest stock market news",
    "Price of Bitcoin today",
    "Stock market trends",
    
    # Technology and computing
    "Explain quantum computing",
    "Define machine learning",
    "What is blockchain?",
    "Explain neural networks",
    "Search for Python programming tutorials",
    "How does cloud computing work?",
    "Latest developments in AI",
    
    # Science and education
    "Find information about climate change",
    "Explain photosynthesis",
    "What is the theory of relativity?",
    "How do vaccines work?",
    "Define DNA",
    "Explain the water cycle",
    
    # Sports and entertainment
    "Who won the latest sports championship?",
    "Latest sports news",
    "Current movie releases",
    "Popular music artists",
    
    # Health and lifestyle
    "Healthy diet recommendations",
    "Exercise benefits",
    "Mental health resources",
    "Nutrition facts",
    
    # General knowledge
    "Who invented the telephone?",
    "What is the capital of France?",
    "Explain the solar system",
    "History of the internet",
    "How does the human brain work?",
    
    # Image searches
    "Image of a sunset",
    "Show me images of mountains",
    "Picture of a cat",
    "Images of space",
    "Show me pictures of nature",
    
    # Search queries
    "Search for cooking recipes",
    "Find information about renewable energy",
    "Search for travel destinations",
    "Find information about space exploration",
    "Search for educational resources",
    
    # Current events and trends
    "Latest technology trends",
    "Current events in science",
    "Recent scientific discoveries",
    "Latest space missions",
    "Current environmental issues"
]


def run_local_query(query: str, logger: TrafficLogger) -> Dict[str, Any]:
    """
    Run a query using local SearxNG + Local LLM
    Returns timing and result info
    """
    start_time = time.time()
    result = {
        "query": query,
        "system": "local",
        "start_time": datetime.now().isoformat(),
        "success": False,
        "error": None,
        "response": None,
        "response_time": 0
    }
    
    try:
        # Check if query should trigger search
        query_lower = query.lower()
        should_search = any(keyword in query_lower for keyword in config.SEARCH_TRIGGER_KEYWORDS)
        is_image = any(keyword in query_lower for keyword in config.IMAGE_SEARCH_TRIGGER_KEYWORDS)
        
        search_context = None
        if should_search or is_image:
            # Perform SearxNG search
            search_type = "image" if is_image else "text"
            search_url = f"{config.SEARXNG_URL}/search"
            params = {"q": query, **config.SEARXNG_PARAMS}
            if is_image:
                params["categories"] = "images"
            
            # Log search request
            logger.log_request(
                method="GET",
                url=search_url,
                params=params,
                query_type="search",
                query_text=query
            )
            
            search_start = time.time()
            response = requests.get(search_url, params=params, timeout=config.REQUEST_TIMEOUT)
            search_time = time.time() - search_start
            
            logger.log_response(
                request_log={"url": search_url, "domain": config.SEARXNG_URL.split("://")[1].split("/")[0]},
                status_code=response.status_code,
                response_size=len(response.content),
                response_time=search_time
            )
            
            if response.status_code == 200:
                results = response.json()
                if "results" in results and results["results"]:
                    if is_image:
                        search_context = "Image search completed"
                    else:
                        search_context = "\n".join([
                            f"{i+1}. {r.get('title', '')}: {r.get('content', '')[:100]}"
                            for i, r in enumerate(results["results"][:config.MAX_SEARCH_RESULTS])
                        ])
        
        # Query Local LLM
        final_prompt = query
        if search_context:
            final_prompt = f"Based on the following web search results:\n{search_context}\n\nUser question: {query}"
        
        messages = []
        if config.SYSTEM_PROMPT:
            messages.append({"role": "system", "content": config.SYSTEM_PROMPT})
        messages.append({"role": "user", "content": final_prompt})
        
        payload = {
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 1000,
            "stream": False
        }
        if config.LOCAL_LM_MODEL:
            payload["model"] = config.LOCAL_LM_MODEL
        
        # Log LLM request
        logger.log_request(
            method="POST",
            url=config.LOCAL_LM_URL,
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            query_type="llm",
            query_text=query
        )
        
        llm_start = time.time()
        response = requests.post(
            config.LOCAL_LM_URL,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=300
        )
        llm_time = time.time() - llm_start
        
        logger.log_response(
            request_log={"url": config.LOCAL_LM_URL, "domain": "127.0.0.1"},
            status_code=response.status_code,
            response_size=len(response.content),
            response_time=llm_time
        )
        
        if response.status_code == 200:
            result_data = response.json()
            if "choices" in result_data and result_data["choices"]:
                result["response"] = result_data["choices"][0].get("message", {}).get("content", "")
                result["success"] = True
        
        result["response_time"] = time.time() - start_time
        
    except Exception as e:
        result["error"] = str(e)
        result["response_time"] = time.time() - start_time
    
    result["end_time"] = datetime.now().isoformat()
    return result


def run_benchmark(queries: List[str] = None, output_file: str = "benchmark_results.json"):
    """
    Run benchmark queries and log traffic
    
    Args:
        queries: List of queries to run (defaults to BENCHMARK_QUERIES)
        output_file: Output file for results
    """
    if queries is None:
        queries = BENCHMARK_QUERIES
    
    logger = TrafficLogger(f"traffic_log_local_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
    logger.start_session("local_benchmark")
    
    print(f"Running {len(queries)} queries on local system...")
    print("=" * 60)
    
    results = []
    for i, query in enumerate(queries, 1):
        print(f"\n[{i}/{len(queries)}] Query: {query}")
        result = run_local_query(query, logger)
        results.append(result)
        
        if result["success"]:
            print(f"  ✓ Success ({result['response_time']:.2f}s)")
            print(f"  Response: {result['response'][:100]}...")
        else:
            print(f"  ✗ Failed: {result.get('error', 'Unknown error')}")
    
    # Export results
    output_data = {
        "benchmark_date": datetime.now().isoformat(),
        "system": "local",
        "queries": results,
        "traffic_summary": logger.get_summary()
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2)
    
    # Export traffic summary
    logger.export_summary(f"traffic_summary_local_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    
    print("\n" + "=" * 60)
    print("Benchmark complete!")
    print(f"Results saved to: {output_file}")
    print(f"Traffic summary: {logger.get_summary()}")
    
    return output_data


if __name__ == "__main__":
    # Allow custom queries from command line or specify count
    queries = None
    count = None
    
    if len(sys.argv) > 1:
        # Check if first arg is a number (count)
        try:
            count = int(sys.argv[1])
            # If it's a number, use that many queries from default list
            queries = BENCHMARK_QUERIES[:count] if count <= len(BENCHMARK_QUERIES) else BENCHMARK_QUERIES
            print(f"Running first {len(queries)} queries from default set...")
        except ValueError:
            # If not a number, treat as custom queries
            queries = sys.argv[1:]
    
    run_benchmark(queries)

