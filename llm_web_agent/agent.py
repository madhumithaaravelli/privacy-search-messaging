import requests
import json
from urllib.parse import urlencode, quote_plus, urljoin
import sys
import os
import re
import time
import threading

# Attempt to import configuration, handle potential import error
try:
    import config
except ImportError:
    print("ERROR: config.py not found. Please ensure it exists in the same directory.")
    sys.exit(1)

# --- Helper Function Enums/Constants ---
class SearchType:
    NONE = 0
    TEXT = 1
    IMAGE = 2

# --- Helper Functions ---

def get_search_type(prompt: str) -> SearchType:
    """Checks if the prompt contains trigger keywords for text or image search."""
    if not prompt:
        return SearchType.NONE
    prompt_lower = prompt.lower()
    # Check for image keywords first
    for keyword in config.IMAGE_SEARCH_TRIGGER_KEYWORDS:
        if keyword in prompt_lower:
            return SearchType.IMAGE
    # Then check for standard text search keywords
    for keyword in config.SEARCH_TRIGGER_KEYWORDS:
        if keyword in prompt_lower:
            return SearchType.TEXT
    return SearchType.NONE

def perform_searxng_search(query: str, search_type: SearchType) -> tuple[str | None, list[str] | None]:
    """Queries the SearxNG instance and returns (text_context, image_urls)."""
    text_context = None
    image_urls = None

    try:
        base_url = config.SEARXNG_URL
        if not base_url.endswith('/'):
            base_url += '/'

        search_path = "search"
        query_params = {"q": query}
        if hasattr(config, "SEARXNG_PARAMS"):
            query_params.update(config.SEARXNG_PARAMS)

        # Add category for image search
        if search_type == SearchType.IMAGE:
            query_params["categories"] = "images"

        encoded_params = urlencode(query_params)
        search_url = urljoin(base_url, search_path) + "?" + encoded_params

        response = requests.get(search_url, timeout=getattr(config, "REQUEST_TIMEOUT", 30))
        response.raise_for_status()
        results = response.json()

        if "results" in results and results["results"]:
            if search_type == SearchType.IMAGE:
                image_urls = []
                for result in results["results"][:getattr(config, "MAX_SEARCH_RESULTS", 5)]:
                    img_src = result.get("img_src")
                    if img_src:
                        if img_src.startswith('/'):
                            img_src = urljoin(config.SEARXNG_URL, img_src)
                        image_urls.append(img_src)
            else:
                text_context = "Web search results:\n"
                for i, result in enumerate(results["results"][:getattr(config, "MAX_SEARCH_RESULTS", 5)]):
                    title = result.get("title", "No Title")
                    content = result.get("content", result.get("snippet", "No Content"))
                    url = result.get("url", "No URL")
                    content_cleaned = ' '.join(content.split()) if content else "N/A"
                    text_context += f"{i+1}. Title: {title}\n   Content: {content_cleaned}\n   URL: {url}\n"
                text_context = text_context.strip()
        else:
            print("--- SearxNG returned no results or unexpected format. ---")

    except requests.exceptions.Timeout:
        print(f"ERROR: Request to SearxNG timed out.")
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Could not connect to SearxNG at {config.SEARXNG_URL}. Error: {e}")
    except json.JSONDecodeError:
        print("ERROR: Failed to decode JSON response from SearxNG.")
    except Exception as e:
        print(f"ERROR: Unexpected error during SearxNG search: {e}")

    return text_context, image_urls


def remove_think_tags(text: str) -> str:
    """Removes <think>...</think> blocks from text."""
    if not text:
        return ""
    return re.sub(r'<think\s*>.*?</think\s*>', '', text, flags=re.DOTALL | re.IGNORECASE).strip()


# --- FIXED Ollama-Compatible Function ---
def query_local_lm(prompt: str, search_context: str | None, history: list[dict]) -> str | None:
    """Sends the prompt (with optional context) to the Local Ollama model."""
    final_prompt = prompt
    if search_context:
        final_prompt = f"Based on the following web search results:\n{search_context}\n\nUser question: {prompt}"

    payload = {
        "model": config.LOCAL_LM_MODEL,
        "prompt": final_prompt,
        "stream": False
    }

    local_lm_timeout = 300
    try:
        response = requests.post(
            f"{config.LOCAL_LM_URL}/api/generate",
            json=payload,
            timeout=local_lm_timeout
        )
        response.raise_for_status()
        result = response.json()
        return result.get("response", "").strip()

    except requests.exceptions.Timeout:
        print(f"\nERROR: Request to Local LM timed out ({local_lm_timeout}s).")
    except requests.exceptions.RequestException as e:
        print(f"\nERROR: Could not connect to Local LM at {config.LOCAL_LM_URL}. Error: {e}")
    except json.JSONDecodeError:
        print("\nERROR: Failed to decode JSON response from Ollama.")
    except Exception as e:
        print(f"\nERROR: Unexpected error during Ollama query: {e}")

    return None


# --- Waiting Animation ---
def animate_waiting(stop_event):
    """Displays a simple waiting animation."""
    animation = ["   ", ".  ", ".. ", "..."]
    idx = 0
    while not stop_event.is_set():
        print(f"\rWaiting for LLM {animation[idx % len(animation)]}", end="")
        idx += 1
        time.sleep(0.3)
    print("\r" + " " * 30 + "\r", end="")


# --- Main Application Logic ---
def main():
    """Main loop to get user input and process it."""
    print("LLM Web Agent Initialized. Type 'quit' or 'exit' to end.")
    print("-" * 30)

    conversation_history = []

    while True:
        try:
            user_prompt = input("You: ")
            if user_prompt.lower() in ["quit", "exit"]:
                break
            if not user_prompt:
                continue

            search_type = get_search_type(user_prompt)
            text_search_context = None
            image_urls = None
            llm_response = None

            if search_type != SearchType.NONE:
                text_search_context, image_urls = perform_searxng_search(user_prompt, search_type)

            if search_type == SearchType.IMAGE:
                if image_urls:
                    print("\nFound Image URLs:")
                    print("-" * 15)
                    for url in image_urls:
                        print(url)
                    print("-" * 15 + "\n")
                else:
                    print("\nNo images found for your query.\n")
                continue

            stop_indicator = threading.Event()
            indicator_thread = threading.Thread(target=animate_waiting, args=(stop_indicator,))
            indicator_thread.start()

            try:
                llm_response = query_local_lm(user_prompt, text_search_context, conversation_history)
            finally:
                stop_indicator.set()
                indicator_thread.join()

            print("\nLLM Response:")
            print("-" * 15)
            if llm_response:
                print(remove_think_tags(llm_response))
                conversation_history.append({"role": "user", "content": user_prompt})
                conversation_history.append({"role": "assistant", "content": llm_response})
            else:
                print("Failed to get a response or process the request.")
            print("-" * 15 + "\n")

        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except EOFError:
            print("\nExiting...")
            break


if __name__ == "__main__":
    if not config.LOCAL_LM_URL or not config.SEARXNG_URL:
        print("ERROR: LOCAL_LM_URL or SEARXNG_URL is not set in config.py.")
        sys.exit(1)
    main()
