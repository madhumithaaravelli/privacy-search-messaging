# 🌐 Local model (Ollama)
LOCAL_LM_URL = "http://localhost:11434"   # URL of the local Ollama API
MODEL = "mistral"                         # Ollama model name
LOCAL_LM_MODEL = "mistral"

# 🔍 Local search engine (SearxNG)
SEARXNG_URL = "http://localhost:8080"     # Local SearxNG instance
MAX_RESULTS = 5                           # Number of search results to fetch

# 🧠 Triggers & behavior tuning
IMAGE_SEARCH_TRIGGER_KEYWORDS = [
    "image", "photo", "picture", "diagram", "chart", "graph"
]
CODE_SEARCH_TRIGGER_KEYWORDS = [
    "code", "snippet", "example", "function", "python", "java", "api"
]
NEWS_SEARCH_TRIGGER_KEYWORDS = [
    "news", "trend", "update", "recent", "current", "today"
]
SEARCH_TRIGGER_KEYWORDS = [
    "search", "find", "information", "details", "explain", "about", "summarize"
]

# ⚙️ Response settings
MAX_TOKENS = 1024                         # Response length limit (varies per model)
TEMPERATURE = 0.7                         # Creativity level for LLM generation

# 🪣 Optional file output (set True to save responses)
SAVE_RESPONSES = False
OUTPUT_DIR = "responses"

# 🧾 Logging
LOGGING_ENABLED = True
LOG_FILE = "agent_log.txt"

SYSTEM_PROMPT = """You are a helpful and privacy-preserving AI assistant.
You have access to a local search engine (SearxNG) and a local LLM (Ollama).
Use the search results only when necessary, summarize clearly, and keep answers concise.
Do not make external network requests or mention any remote APIs."""
