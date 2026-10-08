import os
import google.generativeai as genai

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
AI_ENABLED = os.getenv("AI_ENABLED", "False").lower() in ("true", "1", "t", "yes")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

async def generate_remediation_patch(vulnerability_type: str, context: str) -> dict:
    fallback = {
        "patch": "# Fallback: Isolate network segment manually.",
        "source": "deterministic"
    }
    
    if not AI_ENABLED or not GEMINI_API_KEY:
        return fallback

    system_instruction = "You are an enterprise cybersecurity expert. Provide a strict, CLI-based remediation patch (e.g., iptables, nginx config) for the provided vulnerability. No markdown fluff, no greetings."
    
    try:
        model = genai.GenerativeModel("gemini-1.5-flash", system_instruction=system_instruction)
        prompt = f"Vulnerability: {vulnerability_type}\nContext: {context}"
        
        response = await model.generate_content_async(prompt)
        
        if response.text:
            return {"patch": response.text.strip(), "source": "ai"}
        return fallback
    except Exception as e:
        # Fallback on any AI failure
        return fallback
