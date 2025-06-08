from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import vt
import os
import re
import asyncio
from dotenv import load_dotenv
from pydantic import BaseModel
from typing import Optional

load_dotenv()

app = FastAPI()

# CORS middleware to allow extension to communicate with backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY = os.getenv("VT_API")
if not API_KEY:
    raise ValueError("VT_API key not found in environment variables")

class ScanRequest(BaseModel):
    message: str

class EmailScanRequest(BaseModel):
    message: str
    analyze_content: Optional[bool] = True

async def scan_url(client, url):
    """Submits a URL to VirusTotal for scanning and returns the analysis ID."""
    try:
        analysis = await client.scan_url_async(url)
        return analysis.id
    except Exception as e:
        print(f"Error scanning {url}: {e}")
        return None

async def get_scan_result(client, analysis_id):
    """Retrieves scan results using the analysis ID."""
    while True:
        try:
            analysis = await client.get_object_async(f"/analyses/{analysis_id}")
            if analysis.status == "completed":
                return analysis.stats
            await asyncio.sleep(5)
        except Exception as e:
            print(f"Error fetching scan results: {e}")
            return None

async def process_urls(urls):
    """Handles the scanning and result retrieval asynchronously."""
    results = {}
    async with vt.Client(API_KEY) as client:
        scan_tasks = {url: scan_url(client, url) for url in urls}
        scan_ids = {url: scan_id for url, scan_id in zip(scan_tasks.keys(), await asyncio.gather(*scan_tasks.values())) if scan_id}

        # Fetch results
        for url, scan_id in scan_ids.items():
            stats = await get_scan_result(client, scan_id)
            results[url] = "UNSAFE" if stats and (
                stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0) else "SAFE"
    return results

def extract_urls(message):
    """Extracts URLs from the message using regex."""
    url_regex = r'https?://[^\s,]+'
    return re.findall(url_regex, message)

def analyze_email_content(email_content):
    """Analyzes email content for phishing indicators."""
    indicators = {
        "suspicious_phrases": [],
        "urgency_indicators": 0,
        "grammar_issues": 0
    }
    
    # Check for suspicious phrases
    suspicious_phrases = [
        "verify your account", "update your information", "confirm your details",
        "unusual activity", "suspicious activity", "click here", "login to continue",
        "your account will be suspended", "limited time offer", "act now"
    ]
    
    for phrase in suspicious_phrases:
        if phrase.lower() in email_content.lower():
            indicators["suspicious_phrases"].append(phrase)
    
    # Check for urgency indicators
    urgency_words = ["urgent", "immediately", "now", "today", "asap", "expires", "limited"]
    for word in urgency_words:
        if re.search(r'\b' + word + r'\b', email_content.lower()):
            indicators["urgency_indicators"] += 2
    
    # Simple grammar check (very basic)
    grammar_issues = ["to received", "kindly replied", "to confirmed", "your details is"]
    for issue in grammar_issues:
        if issue.lower() in email_content.lower():
            indicators["grammar_issues"] += 2
    
    return indicators

@app.post("/scan")
async def scan_urls(request: ScanRequest):
    """Endpoint to process incoming requests for URL scanning."""
    urls = extract_urls(request.message)
    if not urls:
        raise HTTPException(status_code=400, detail="No URLs found in message")
    
    try:
        results = await process_urls(urls)
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan_email")
async def scan_email(request: EmailScanRequest):
    """Endpoint to process incoming email content."""
    email_content = request.message
    
    # Extract and scan URLs
    urls = extract_urls(email_content)
    url_results = {}
    if urls:
        url_results = await process_urls(urls)
    
    # Analyze email content if requested
    content_analysis = {}
    if request.analyze_content:
        content_analysis = analyze_email_content(email_content)
    
    # Determine overall safety
    is_safe = True
    unsafe_reasons = []
    
    # Check for unsafe URLs
    if "UNSAFE" in url_results.values():
        is_safe = False
        unsafe_reasons.append("Contains potentially malicious URLs")
    
    # Check for suspicious phrases (increased threshold from 1 to 2)
    if len(content_analysis.get("suspicious_phrases", [])) >= 3:
        is_safe = False
        unsafe_reasons.append(f"Contains {len(content_analysis['suspicious_phrases'])} suspicious phrases")
    
    # Check for urgency indicators (kept threshold at 2)
    if content_analysis.get("urgency_indicators", 0) >= 2:
        is_safe = False
        unsafe_reasons.append(f"Contains {content_analysis['urgency_indicators']} urgency indicators")
    
    # Check for grammar issues
    if content_analysis.get("grammar_issues", 0) >= 1:
        is_safe = False
        unsafe_reasons.append("Contains suspicious grammar patterns")
    
    recommendation = "This content appears to be safe." if is_safe else "This content shows signs of being a phishing attempt."
    if not is_safe and unsafe_reasons:
        recommendation += " Reasons: " + ", ".join(unsafe_reasons) + "."
    
    return {
        "safe": is_safe,
        "url_scan": url_results,
        "content_analysis": content_analysis if request.analyze_content else None,
        "recommendation": recommendation
    }

@app.post("/scan-url")
async def scan_single_url(request: ScanRequest):
    """Endpoint for the browser extension to scan single URLs"""
    urls = extract_urls(request.message)
    if not urls:
        raise HTTPException(status_code=400, detail="No URL found in message")
    
    try:
        results = await process_urls(urls)
        threat_level = "malicious" if results.get(urls[0]) == "UNSAFE" else "harmless"
        return {
            "url": urls[0],
            "threat_level": threat_level,
            "result": results[urls[0]]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)