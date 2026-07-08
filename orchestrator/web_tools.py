import asyncio, json
import re
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger("web_tools")


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str


@dataclass
class FetchResult:
    url: str
    title: str
    content: str


async def web_search(query: str, max_results: int = 5) -> List[SearchResult]:
    """Search the web using DuckDuckGo with fallback to HTML scraping."""
    results = []
    
    # Try ddgs library first
    try:
        from ddgs import DDGS
        def _ddgs():
            with DDGS() as ddgs:
                return list(ddgs.text(query, max_results=max_results))
        raw = await asyncio.wait_for(asyncio.to_thread(_ddgs), timeout=20)
        for r in raw:
            results.append(SearchResult(
                title=r.get("title", ""),
                url=r.get("href", ""),
                snippet=r.get("body", "")
            ))
        if results:
            return results[:max_results]
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"ddgs failed: {e}")
    
    # Fallback to HTML scraping
    return await _html_search(query, max_results)


async def _html_search(query: str, max_results: int = 5) -> List[SearchResult]:
    """Search via DuckDuckGo API and HTML scraping."""
    import httpx
    results = []
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            # Try the DuckDuckGo API first
            resp = await client.get(
                f"https://api.duckduckgo.com/?q={query.replace(' ', '+')}&format=json",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                abstract = data.get("AbstractText", "")
                source = data.get("AbstractSource", "")
                url = data.get("AbstractURL", "")
                if url:
                    results.append(SearchResult(title=source or "Result", url=url, snippet=abstract[:200]))
                for topic in data.get("RelatedTopics", [])[:max_results]:
                    if "Text" in topic and "FirstURL" in topic:
                        results.append(SearchResult(
                            title=topic.get("Text", "").split(" - ")[0][:80],
                            url=topic["FirstURL"],
                            snippet=topic.get("Text", "")[:200]
                        ))
            if results:
                return results[:max_results]

            # Fallback: HTML scrape
            resp = await client.get(
                "https://lite.duckduckgo.com/lite/?q=" + query.replace(" ", "+"),
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"},
            )
            html = resp.text
            rows = re.findall(r'<a[^>]*href="(https?://[^"]+)"[^>]*>([^<]+)</a>', html)
            seen = set()
            for url, title in rows:
                if url not in seen:
                    seen.add(url)
                    results.append(SearchResult(title=title.strip()[:80], url=url, snippet=""))
    except Exception as e:
        logger.warning(f"HTML search failed: {e}")
    return results[:max_results]


async def fetch_url(url: str, max_length: int = 8000) -> FetchResult:
    """Fetch and extract text content from a URL."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            text = resp.text
            
            # Extract title
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', text, re.IGNORECASE)
            title = title_match.group(1).strip() if title_match else ""
            
            # Remove scripts and styles
            text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
            text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
            
            # Remove HTML tags
            text = re.sub(r'<[^>]+>', ' ', text)
            
            # Normalize whitespace
            text = re.sub(r'\s+', ' ', text).strip()
            
            return FetchResult(url=url, title=title, content=text[:max_length])
    except Exception as e:
        logger.warning(f"Fetch failed for {url}: {e}")
        return FetchResult(url=url, title="", content=f"Error fetching: {e}")


# Tool definitions for function calling
WEB_SEARCH_TOOL = {
    "type": "function",
    "function": {
        "name": "web_search",
        "description": "Search the web for current information. Use this when you need up-to-date information, recent news, or information not in your training data.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query string"
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 5)",
                    "default": 5
                }
            },
            "required": ["query"]
        }
    }
}

FETCH_URL_TOOL = {
    "type": "function",
    "function": {
        "name": "fetch_url",
        "description": "Fetch and extract text content from a specific URL. Use this when you need to read the full content of a specific page.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to fetch content from"
                },
                "max_length": {
                    "type": "integer",
                    "description": "Maximum content length to return (default: 8000)",
                    "default": 8000
                }
            },
            "required": ["url"]
        }
    }
}

AVAILABLE_TOOLS = [WEB_SEARCH_TOOL, FETCH_URL_TOOL]


async def execute_tool_call(tool_name: str, arguments: dict) -> Any:
    """Execute a tool call and return the result."""
    if tool_name == "web_search":
        query = arguments.get("query", "")
        max_results = arguments.get("max_results", 5)
        results = await web_search(query, max_results)
        return [{"title": r.title, "url": r.url, "snippet": r.snippet} for r in results]
    
    elif tool_name == "fetch_url":
        url = arguments.get("url", "")
        max_length = arguments.get("max_length", 8000)
        result = await fetch_url(url, max_length)
        return {"url": result.url, "title": result.title, "content": result.content}
    
    else:
        return {"error": f"Unknown tool: {tool_name}"}


def format_search_results(results: List[SearchResult]) -> str:
    """Format search results for model consumption."""
    if not results:
        return "No results found."
    
    lines = [f"Found {len(results)} results:"]
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r.title}")
        lines.append(f"   URL: {r.url}")
        if r.snippet:
            lines.append(f"   Snippet: {r.snippet}")
        lines.append("")
    return "\n".join(lines)


def format_fetch_result(result: FetchResult) -> str:
    """Format fetch result for model consumption."""
    if not result.content or result.content.startswith("Error"):
        return f"Failed to fetch {result.url}: {result.content}"
    
    return f"Title: {result.title}\nURL: {result.url}\n\nContent:\n{result.content}"