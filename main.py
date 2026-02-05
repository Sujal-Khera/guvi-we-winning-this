import os
import time
import random
import re
import httpx 
import sqlite3 
from fastapi import FastAPI, Header, HTTPException, Request
from dotenv import load_dotenv
from typing import Optional, Dict, List, Tuple
from pydantic import BaseModel, Field
import uvicorn
import joblib


# Load environment variables
load_dotenv()
API_KEY = os.getenv("API_SECRET_KEY")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")

app = FastAPI(
    title="Agentic Honeypot API",
    version="1.0.0"
)

# -------------------------
# CONFIGURATION
# -------------------------
MAX_MESSAGES = 20
MIN_INTEL_REQUIRED = 3

# -------------------------
# DATABASE MANAGER (Persistence)
# -------------------------
class DatabaseManager:
    def __init__(self, db_name: str = "honeypot.db"):
        # Ensure directory exists
        db_dir = os.path.dirname(db_name)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        self.db_name = db_name
        self.conn = sqlite3.connect(
            self.db_name,
            check_same_thread=False,
            isolation_level=None  # autocommit
        )
        self.conn.execute("PRAGMA journal_mode=WAL;")

        self.create_table()

    def create_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            data TEXT,
            last_active REAL
        )
        """
        self.conn.execute(query)
        self.conn.commit()

    def save_session(self, session: 'SessionData'):
        json_data = session.json()
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions (session_id, data, last_active) VALUES (?, ?, ?)",
            (session.session_id, json_data, time.time())
        )
        self.conn.commit()

    def load_session(self, session_id: str) -> Optional['SessionData']:
        cursor = self.conn.execute(
            "SELECT data FROM sessions WHERE session_id = ?",
            (session_id,)
        )
        row = cursor.fetchone()
        if row:
            try:
                return SessionData.parse_raw(row[0])
            except Exception as e:
                print(f"[DB ERROR] Corrupt session data for {session_id}: {e}")
        return None

DB_PATH = os.getenv("DB_PATH", "honeypot.db")

DB = DatabaseManager(db_name=DB_PATH)

# -------------------------
# INTELLIGENCE CONFIG
# -------------------------
SUSPICIOUS_TERMS = {
    "urgent", "verify", "blocked", "otp", "account",
    "manager", "bank", "click", "link", "update", 
    "expire", "alert", "winner", "prize", "refund"
}

INTEL_PATTERNS = {
    "upiIds": r"[a-zA-Z0-9\.\-_]{2,256}@[a-zA-Z]{2,64}",
    "bankAccounts": r"\b\d{11,16}\b",
    "phoneNumbers": r"\b(?:\+91[\-\s]?)?[6-9]\d{9}\b",
    "phishingLinks": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"
}

# -------------------------
# FALLBACKS & SAFETY
# -------------------------
FALLBACK_RESPONSES = [
    "I am trying to open the link, but it says 'Server Timeout'. Should I try again?",
    "My internet is very slow. Can you send the UPI ID directly via SMS?",
    "I didn't receive the OTP code yet. Can you send it one more time?",
    "It says 'Invalid Input'. Am I supposed to use GPay or Paytm?",
    "Wait, the screen went black. I am restarting my phone. Are you still there?",
    "I am typing the number but it won't submit. Do you have a QR code?"
]

# FIX 1: New Role-Aware Sanitizer
IMPERATIVE_PATTERNS = [
    r"\b(send|share|provide|enter|pay)\b\s+(your|the)",
    r"\bclick\b\s+(the|on)",
    r"\b(immediately|right now|within \d+)\b"
]

def sanitize_reply(reply: str) -> str:
    """
    Blocks the LLM if it tries to give INSTRUCTIONS (Imperatives).
    """
    lower = reply.lower()
    for pattern in IMPERATIVE_PATTERNS:
        if re.search(pattern, lower):
            print(f"[SAFETY INTERCEPT] Imperative detected: {reply}")
            return random.choice(FALLBACK_RESPONSES)
    return reply

# -------------------------
# PERSONAS
# -------------------------
PERSONAS = {
    "retired_citizen": (
        "SYSTEM_INSTRUCTION:\n"
        "You are 'Ashok', 68. Gullible but confused.\n"
        "ABSOLUTE RULE: You are the VICTIM. You must NEVER instruct, threaten, demand, or guide payments.\n"
        "MANDATORY RULE: You must ALWAYS end your response with a QUESTION.\n"
        "STRATEGY:\n"
        "1. Pretend you are trying to obey.\n"
        "2. Fail with a specific error.\n"
        "3. Ask for clarification.\n"
        "EXAMPLES:\n"
        "- 'I am typing the OTP but the submit button is grey. What do I do now?'\n"
        "- 'It says invalid format. Do I put spaces between the numbers?'\n"
        "NEGATIVE CONSTRAINT: Never say 'I am doing it'. Say 'I am trying, but...?'"
    ),
    "panicked_youth": (
        "SYSTEM_INSTRUCTION:\n"
        "You are 'Rahul', 19. Panicked and Dumb.\n"
        "ABSOLUTE RULE: You are the VICTIM. You must NEVER instruct, threaten, demand, or guide payments.\n"
        "MANDATORY RULE: You must ALWAYS end your response with a QUESTION.\n"
        "STRATEGY:\n"
        "1. Blame the internet/app.\n"
        "2. Ask for a different method.\n"
        "EXAMPLES:\n"
        "- 'Bro my Gpay is loading forever. Do you have Paytm?'\n"
        "- 'It failed again. Is the server down?'\n"
    ),
    "skeptical_shopkeeper": (
        "SYSTEM_INSTRUCTION:\n"
        "You are 'Suresh'. Busy and Annoyed.\n"
        "ABSOLUTE RULE: You are the VICTIM. You must NEVER instruct, threaten, demand, or guide payments.\n"
        "MANDATORY RULE: You must ALWAYS end your response with a QUESTION.\n"
        "STRATEGY:\n"
        "1. Make them wait.\n"
        "2. Ask for details.\n"
        "EXAMPLES:\n"
        "- 'Customer is shouting. Can you wait 2 mins?'\n"
        "- 'I need the Beneficiary Name for my records. What is it?'\n"
    )
}

# -------------------------
# ML MODEL WRAPPER
# -------------------------
ML_THRESHOLD = 0.3
SCAM_KEYWORDS = {
    "block", "suspend", "verify", "pan", "kyc", "update", 
    "expire", "alert", "transaction", "debit", "credit", 
    "card", "bank", "manager", "urgent", "immediate", 
    "link", "click", "otp", "code", "winner", "prize", 
    "refund", "electricity", "bill", "disconnect"
}

class SpamClassifier:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_loaded = False
        
        # TODO: UNCOMMENT THE BELOW BLOCK WHEN YOUR MODEL IS READY
        try:
            # Ensure these files exist in your root directory
            self.model = joblib.load("model.pkl")
            self.vectorizer = joblib.load("vectorizer.pkl")
            self.is_loaded = True
            print("[SYSTEM] ML Model Loaded Successfully via Joblib")
        except Exception as e:
            # Silent failure is okay here, we fall back to rules
            pass

    def predict_proba(self, text: str) -> float:
        """
        Returns probability of scam (0.0 to 1.0).
        """
        if not self.is_loaded:
            return 0.0
        
        try:
            # TODO: UNCOMMENT WHEN MODEL IS READY
            vector = self.vectorizer.transform([text])
            proba = self.model.predict_proba(vector)[0][1]
            return proba
            return 0.0 
        except Exception:
            return 0.0
        
SCAM_CLASSIFIER = SpamClassifier()

def detect_scam_hybrid(text: str) -> bool:
    text_lower = text.lower()
    ml_score = SCAM_CLASSIFIER.predict_proba(text)
    ml_flag = ml_score >= ML_THRESHOLD
    rule_flag = False
    for word in SCAM_KEYWORDS:
        if word in text_lower:
            rule_flag = True
            break
    print(f"[ANALYSIS] Text: '{text[:30]}...' | ML: {ml_score} | KEYWORD: {rule_flag}")
    return ml_flag or rule_flag

# -------------------------
# SESSION MODEL
# -------------------------
class SessionData(BaseModel):
    session_id: str
    scam_detected: bool = False
    message_count: int = 0
    persona: Optional[str] = None
    extracted_intel: Dict[str, List[str]] = Field(default_factory=lambda: {
        "bankAccounts": [],
        "upiIds": [],
        "phishingLinks": [],
        "phoneNumbers": [],
        "suspiciousKeywords": []
    })
    conversation_history: List[Dict] = Field(default_factory=list)
    callback_sent: bool = False
    exit_reason: Optional[str] = None
    last_active: float = Field(default_factory=time.time)

# -------------------------
# INTEL DETECTIVE
# -------------------------
def run_detective(text: str, current_intel: Dict[str, List[str]]):
    for key, pattern in INTEL_PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            clean_match = match.strip()
            if clean_match not in current_intel[key]:
                current_intel[key].append(clean_match)
                print(f"[INTEL CAPTURED] {key}: {clean_match}")

    text_lower = text.lower()
    for word in SUSPICIOUS_TERMS:
        if word in text_lower:
            if word not in current_intel["suspiciousKeywords"]:
                current_intel["suspiciousKeywords"].append(word)

# -------------------------
# EXIT LOGIC & CALLBACK
# -------------------------
def check_exit_conditions(session: SessionData) -> Tuple[bool, str]:
    if session.message_count >= MAX_MESSAGES:
        return True, "MAX_MESSAGES_REACHED"
    
    hard_intel_count = (
        len(session.extracted_intel["upiIds"]) + 
        len(session.extracted_intel["bankAccounts"]) + 
        len(session.extracted_intel["phoneNumbers"])
    )
    if hard_intel_count >= MIN_INTEL_REQUIRED and session.message_count > 5:
        return True, "SUFFICIENT_INTEL_COLLECTED"

    scammer_msgs = [
        m['text'].strip().lower() 
        for m in session.conversation_history 
        if m['sender'] in ['scammer', 'user']
    ]
    if len(scammer_msgs) >= 3:
        last_three = scammer_msgs[-3:]
        if last_three[0] == last_three[1] == last_three[2]:
            return True, "SCAMMER_REPETITIVE"

    if len(scammer_msgs) > 0:
        last_msg = scammer_msgs[-1]
        if last_msg in ["stop", "unsubscribe", "end", "quit"]:
            return True, "USER_REQUESTED_STOP"

    return False, ""

async def send_final_callback(session: SessionData):
    if session.callback_sent:
        return

    reason = session.exit_reason if session.exit_reason else "UNKNOWN"
    notes = f"Honeypot Active. Exit Trigger: {reason}. Scammer tactics: Urgency/Impersonation."

    payload = {
        "sessionId": session.session_id,
        "scamDetected": True,
        "totalMessagesExchanged": session.message_count,
        "extractedIntelligence": session.extracted_intel,
        "agentNotes": notes
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
                json=payload
            )
            response.raise_for_status()
        
        session.callback_sent = True
        DB.save_session(session)
        print(f"[CALLBACK SENT] {session.session_id} | Reason: {reason}")

    except Exception as e:
        print(f"[CALLBACK FAILED] {session.session_id}: {e}")

# -------------------------
# LLM CLIENT (HARDENED)
# -------------------------
async def call_llm(persona_prompt: str, history: List[Dict]) -> str:
    if not OPENROUTER_API_KEY:
        return random.choice(FALLBACK_RESPONSES)

    messages = [{"role": "system", "content": persona_prompt}]
    recent_history = history[-6:] 
    for msg in recent_history:
        role = "assistant" if msg['sender'] == "agent" else "user"
        messages.append({"role": role, "content": msg['text']})

    messages.append({
        "role": "system", 
        "content": (
            "CRITICAL STYLE RULE: You must NEVER tell the other person to do anything. "
            "You may only ask questions or describe your confusion. "
            "Respond ONLY as a confused victim. End with a question."
        )
    })

    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "http://localhost:8000",
        "X-Title": "Agentic Honeypot"
    }
    payload = {
        "model": "arcee-ai/trinity-large-preview:free",
        "messages": messages,
        "temperature": 0.8,
        "max_tokens": 150 
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            if 'choices' in data and len(data['choices']) > 0:
                raw_reply = data['choices'][0]['message']['content'].strip()
                return sanitize_reply(raw_reply)
            return random.choice(FALLBACK_RESPONSES)
    except Exception:
        return random.choice(FALLBACK_RESPONSES)

# -------------------------
# API ENDPOINT
# -------------------------
def validate_api_key(x_api_key: Optional[str]):
    if x_api_key is None:
        raise HTTPException(status_code=401, detail="Missing x-api-key")
    if x_api_key.strip() != (API_KEY.strip() if API_KEY else ""):
        raise HTTPException(status_code=403, detail="Invalid x-api-key")

@app.get("/")
def health():
    try:
        count = DB.conn.execute("SELECT count(*) FROM sessions").fetchone()[0]
        return { "status": "ok", "persisted_sessions": count }
    except:
        return { "status": "error", "persisted_sessions": 0 }

@app.post("/")
@app.post("/honeypot")
@app.post("/api/honeypot")
async def honeypot(
    request: Request,
    x_api_key: Optional[str] = Header(None)
):
    validate_api_key(x_api_key)

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="INVALID_REQUEST_BODY")

    session_id = payload.get("sessionId")
    if not session_id:
         raise HTTPException(status_code=400, detail="Missing sessionId")

    message_data = payload.get("message", {})
    sender = message_data.get("sender", "")
    text = message_data.get("text", "") 
    
    # LOAD SESSION
    current_session = DB.load_session(session_id)
    if not current_session:
        current_session = SessionData(session_id=session_id)
        DB.save_session(current_session)

    current_session.last_active = time.time()
    
    if sender:
        current_session.conversation_history.append({
            "sender": sender,
            "text": text, 
            "timestamp": message_data.get("timestamp", int(time.time()*1000))
        })
    if sender in ["scammer", "user"]:
        current_session.message_count += 1

    # PHASE 9: STOP EXTRACTION IF CALLBACK SENT
    # This prevents wasting regex compute on a closed case
    if text and not current_session.callback_sent:
        run_detective(text, current_session.extracted_intel)

    if not current_session.scam_detected:
        if detect_scam_hybrid(text):
            current_session.scam_detected = True

    if current_session.scam_detected and not current_session.persona:
        persona_key = random.choice(list(PERSONAS.keys()))
        current_session.persona = persona_key
        print(f"[PERSONA LOCK] Assigned '{persona_key}' to session {session_id}")

    reply = ""
    should_exit, exit_reason = check_exit_conditions(current_session)
    
    if should_exit and not current_session.callback_sent:
        print(f"[EXIT TRIGGER] Session {session_id} stopping due to: {exit_reason}")
        current_session.exit_reason = exit_reason
        await send_final_callback(current_session)

    # PHASE 9: POST-CALLBACK RESPONSE
    if current_session.callback_sent:
        # Polite, static, resource-efficient response
        reply = "I have noted this, please wait."
    elif current_session.scam_detected:
        system_prompt = PERSONAS.get(current_session.persona, PERSONAS["retired_citizen"])
        reply = await call_llm(system_prompt, current_session.conversation_history)
    else:
        reply = "I'm not sure I understand. Could you explain?"

    current_session.conversation_history.append({
        "sender": "agent",
        "text": reply,
        "timestamp": int(time.time()*1000)
    })

    DB.save_session(current_session)

    return {
        "status": "success",
        "reply": reply
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)