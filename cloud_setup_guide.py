"""
Cloud Benchmark Setup Guide
Instructions for running cloud benchmarks and capturing traffic
"""

import sys


def print_google_setup():
    """Instructions for Google Custom Search API"""
    print("=" * 70)
    print("GOOGLE CUSTOM SEARCH API SETUP")
    print("=" * 70)
    print("\n1. GET API CREDENTIALS:")
    print("   - Go to: https://developers.google.com/custom-search/v1/overview")
    print("   - Click 'Get a Key'")
    print("   - Create a project or select existing")
    print("   - Copy your API Key")
    print("\n2. CREATE SEARCH ENGINE:")
    print("   - Go to: https://programmablesearchengine.google.com/controlpanel/create")
    print("   - Create a new search engine")
    print("   - Set 'Sites to search' to '*' (search entire web)")
    print("   - Copy the 'Search engine ID' (CX)")
    print("\n3. RUN BENCHMARK:")
    print("   Method 1 - With capture script:")
    print("     ./llm_web_agent/run_cloud_benchmark_with_capture.sh google \\")
    print("       --api-key YOUR_API_KEY --cx YOUR_SEARCH_ENGINE_ID")
    print("\n   Method 2 - Direct:")
    print("     python llm_web_agent/cloud_benchmark.py google \\")
    print("       --api-key YOUR_API_KEY --cx YOUR_SEARCH_ENGINE_ID")
    print("\n   Method 3 - Environment variables:")
    print("     export GOOGLE_API_KEY=your_key")
    print("     export GOOGLE_CX=your_search_engine_id")
    print("     python llm_web_agent/cloud_benchmark.py google")
    print("\n4. COST:")
    print("   - Free tier: 100 queries/day")
    print("   - After that: $5 per 1000 queries")
    print("   - 50 queries = Free (within daily limit)")
    print("=" * 70)


def print_openai_setup():
    """Instructions for OpenAI API"""
    print("=" * 70)
    print("OPENAI API SETUP")
    print("=" * 70)
    print("\n1. GET API KEY:")
    print("   - Go to: https://platform.openai.com/api-keys")
    print("   - Sign up or log in")
    print("   - Create a new API key")
    print("   - Copy and save it (you won't see it again!)")
    print("\n2. ADD CREDITS:")
    print("   - Go to: https://platform.openai.com/account/billing")
    print("   - Add payment method and credits")
    print("   - Minimum: $5")
    print("\n3. RUN BENCHMARK:")
    print("   Method 1 - With capture script:")
    print("     ./llm_web_agent/run_cloud_benchmark_with_capture.sh openai \\")
    print("       --api-key YOUR_API_KEY")
    print("\n   Method 2 - Direct:")
    print("     python llm_web_agent/cloud_benchmark.py openai \\")
    print("       --api-key YOUR_API_KEY")
    print("\n   Method 3 - Environment variable:")
    print("     export OPENAI_API_KEY=your_key")
    print("     python llm_web_agent/cloud_benchmark.py openai")
    print("\n4. COST:")
    print("   - GPT-3.5-turbo: ~$0.002 per 1K tokens")
    print("   - 50 queries ≈ $0.10 - $0.50 (depending on response length)")
    print("=" * 70)


def print_comparison_workflow():
    """Complete workflow for comparing local vs cloud"""
    print("=" * 70)
    print("COMPLETE COMPARISON WORKFLOW")
    print("=" * 70)
    print("\nSTEP 1: Run Local Benchmark (Already Done)")
    print("  ✓ Local benchmark with capture")
    print("  ✓ Files created:")
    print("    - capture_benchmark_*.pcap")
    print("    - traffic_log_local_*.jsonl")
    print("    - benchmark_results.json")
    print("\nSTEP 2: Run Cloud Benchmark")
    print("  Choose one:")
    print("    A. Google Search:")
    print("       ./llm_web_agent/run_cloud_benchmark_with_capture.sh google \\")
    print("         --api-key KEY --cx SEARCH_ENGINE_ID")
    print("\n    B. OpenAI:")
    print("       ./llm_web_agent/run_cloud_benchmark_with_capture.sh openai \\")
    print("         --api-key KEY")
    print("\nSTEP 3: Analyze Privacy")
    print("  Local system:")
    print("    python llm_web_agent/privacy_analyzer.py traffic_log_local_*.jsonl")
    print("\n  Cloud system:")
    print("    python llm_web_agent/privacy_analyzer.py traffic_log_cloud_*.jsonl")
    print("\nSTEP 4: Compare Results")
    print("  python -c \"")
    print("    from privacy_analyzer import PrivacyAnalyzer")
    print("    local = PrivacyAnalyzer('traffic_log_local_*.jsonl')")
    print("    cloud = PrivacyAnalyzer('traffic_log_cloud_*.jsonl')")
    print("    comparison = local.compare_with_cloud('traffic_log_cloud_*.jsonl')")
    print("    print(comparison)")
    print("  \"")
    print("\nSTEP 5: Analyze Wireshark Captures")
    print("  Local:")
    print("    wireshark capture_benchmark_*.pcap")
    print("  Cloud:")
    print("    wireshark capture_cloud_*.pcap")
    print("\nSTEP 6: Generate Report")
    print("  Use privacy labels and comparison data for your report")
    print("=" * 70)


def print_all():
    """Print all setup guides"""
    print_google_setup()
    print("\n\n")
    print_openai_setup()
    print("\n\n")
    print_comparison_workflow()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        service = sys.argv[1].lower()
        if service == "google":
            print_google_setup()
        elif service == "openai":
            print_openai_setup()
        elif service == "workflow":
            print_comparison_workflow()
        else:
            print(f"Unknown service: {service}")
            print("Available: google, openai, workflow")
    else:
        print_all()


