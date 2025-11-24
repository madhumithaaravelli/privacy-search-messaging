import json, time, requests, sys

# ✅ Full 50 Benchmark Queries
BENCHMARK_QUERIES = [
    "What is the weather today?",
    "Current weather forecast",
    "What happened in the news today?",
    "Latest news about artificial intelligence",
    "Recent news about technology",
    "Today's top news stories",
    "Current stock price of Apple",
    "Latest stock market news",
    "Price of Bitcoin today",
    "Stock market trends",
    "Explain quantum computing",
    "Define machine learning",
    "What is blockchain?",
    "Explain neural networks",
    "Search for Python programming tutorials",
    "How does cloud computing work?",
    "Latest developments in AI",
    "Find information about climate change",
    "Explain photosynthesis",
    "What is the theory of relativity?",
    "How do vaccines work?",
    "Define DNA",
    "Explain the water cycle",
    "Who won the latest sports championship?",
    "Latest sports news",
    "Current movie releases",
    "Popular music artists",
    "Healthy diet recommendations",
    "Exercise benefits",
    "Mental health resources",
    "Nutrition facts",
    "Who invented the telephone?",
    "What is the capital of France?",
    "Explain the solar system",
    "History of the internet",
    "How does the human brain work?",
    "Image of a sunset",
    "Show me images of mountains",
    "Picture of a cat",
    "Images of space",
    "Show me pictures of nature",
    "Search for cooking recipes",
    "Find information about renewable energy",
    "Search for travel destinations",
    "Find information about space exploration",
    "Search for educational resources",
    "Latest technology trends",
    "Current events in science",
    "Recent scientific discoveries",
    "Latest space missions",
    "Current environmental issues"
]

# 🔧 Ollama config
LOCAL_LM_URL = "http://localhost:11434"
LOCAL_LM_MODEL = "gemma3:4b"

results = []
total = len(BENCHMARK_QUERIES)

for i, q in enumerate(BENCHMARK_QUERIES, start=1):
    print(f"\n[{i}/{total}] Running query: {q[:60]}...", flush=True)
    start = time.time()
    try:
        with requests.post(
            f"{LOCAL_LM_URL}/api/chat",
            json={"model": LOCAL_LM_MODEL, "messages": [{"role": "user", "content": q}]},
            timeout=120,
            stream=True
        ) as resp:
            latency = time.time() - start
            if resp.ok:
                message_parts = []
                print("   ↳ streaming: ", end="", flush=True)
                for line in resp.iter_lines(decode_unicode=True):
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        if "message" in data and "content" in data["message"]:
                            part = data["message"]["content"]
                            message_parts.append(part)
                            print(part, end="", flush=True)
                    except json.JSONDecodeError:
                        continue

                message = "".join(message_parts).strip()
                results.append({
                    "query": q,
                    "response": message,
                    "latency": latency
                })
                print(f"\n   ✅ Done ({latency:.2f}s)")
            else:
                results.append({"query": q, "error": resp.text, "latency": latency})
                print(f"   ❌ Error: {resp.status_code}", flush=True)
    except Exception as e:
        results.append({"query": q, "error": str(e)})
        print(f"   ⚠️ Exception: {e}", flush=True)

# 💾 Save results
output_file = "benchmark_results_gemma3_4b.json"
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2, ensure_ascii=False)

print(f"\n✅ All done — saved as {output_file}")
