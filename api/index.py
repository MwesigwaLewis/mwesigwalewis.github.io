import os
import random
import logging
import sys
import json
import base64
import hashlib
import hmac
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response

# =========================
# VERCEL PATH RESOLUTION
# =========================
# Vercel runs from project root, but api/ is the function entry
# We need to resolve paths relative to this file
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(
    __name__, 
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR,
    static_url_path='/static'
)

app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    # Fallback for local dev, but Vercel should always have this
    app.secret_key = os.urandom(32).hex()

# =========================
# ENTERPRISE LOGGING
# =========================
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if hasattr(record, "path"):
            log_obj["path"] = record.path
        if hasattr(record, "method"):
            log_obj["method"] = record.method
        if hasattr(record, "ip"):
            log_obj["ip"] = record.ip
        if hasattr(record, "user"):
            log_obj["user"] = record.user
        return json.dumps(log_obj, default=str)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JSONFormatter())
app.logger.handlers = []
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)

logger = app.logger

# =========================
# STATELESS SESSION (VERCEL-SAFE)
# =========================
class SecureCookieSession:
    def __init__(self, secret_key):
        self.secret = secret_key.encode() if isinstance(secret_key, str) else secret_key
    
    def _sign(self, data):
        return hmac.new(self.secret, data.encode(), hashlib.sha256).hexdigest()[:32]
    
    def encode(self, data):
        payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
        signature = self._sign(payload)
        return f"{payload}.{signature}"
    
    def decode(self, cookie_value):
        if not cookie_value:
            return {}
        try:
            payload, signature = cookie_value.split('.', 1)
            expected = self._sign(payload)
            if not hmac.compare_digest(signature, expected):
                logger.warning("Session tampering detected")
                return {}
            return json.loads(base64.urlsafe_b64decode(payload.encode()))
        except Exception as e:
            logger.error(f"Session decode error: {e}")
            return {}

session_manager = SecureCookieSession(app.secret_key)

def get_session():
    cookie = request.cookies.get('session', '')
    return session_manager.decode(cookie)

def save_session(response, data):
    encoded = session_manager.encode(data)
    response.set_cookie(
        'session', encoded,
        httponly=True,
        secure=True,
        samesite='Strict',
        max_age=3600
    )
    return response

# =========================
# REQUEST LOGGING
# =========================
@app.before_request
def log_request_info():
    session = get_session()
    extra = {
        "path": request.path,
        "method": request.method,
        "ip": request.headers.get('X-Forwarded-For', request.remote_addr),
        "user": session.get("name", "anonymous"),
    }
    logger.info(f"→ {request.method} {request.path}", extra=extra)

@app.after_request
def log_response_info(response):
    logger.info(f"← {response.status_code} {request.path}")
    return response

# =========================
# AUTH DECORATOR
# =========================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session = get_session()
        if not session.get("auth_complete"):
            logger.warning("Unauthorized access attempt")
            response = make_response(redirect(url_for("auth")))
            return save_session(response, session)
        return f(*args, **kwargs)
    return decorated_function

# =========================
# SAFE CALCULATOR
# =========================
def safe_calculate(expr: str):
    allowed_chars = set("0123456789+-*/().% ")
    
    if not expr or any(c not in allowed_chars for c in expr):
        return "Error"
    
    expr = expr.strip()
    if not expr:
        return "0"
    
    if len(expr) > 200:
        return "Error"
    
    try:
        result = eval(expr, {"__builtins__": None}, {})
        return result
    except Exception as e:
        logger.error(f"Calculation error: {expr} | {e}")
        return "Error"

# =========================
# HINT SYSTEM
# =========================
class AdaptiveHintSystem:
    HINT_LIMITS = {
        "Easy": 5,
        "Medium": 3,
        "Hard": 2,
        "Nightmare": 0
    }
    
    THRESHOLDS = {
        "Easy": 3,
        "Medium": 4,
        "Hard": 5,
        "Nightmare": float('inf')
    }
    
    @classmethod
    def analyze_guess_history(cls, history, secret, difficulty):
        if difficulty == "Nightmare" or not history:
            return False, None, None
        
        wrong_guesses = [g for g in history if g != secret]
        if len(wrong_guesses) < cls.THRESHOLDS[difficulty]:
            return False, None, None
        
        if len(wrong_guesses) >= 3:
            recent = wrong_guesses[-3:]
            directions = ["low" if g < secret else "high" for g in recent]
            
            if len(set(directions)) > 1:
                return True, "direction", "💡 Hint: You're oscillating! Try a number between your last two guesses."
            
            if len(set(directions)) == 1:
                direction = "higher" if directions[0] == "low" else "lower"
                return True, "direction", f"💡 Hint: The number is {direction} than your recent guesses."
        
        if len(wrong_guesses) >= 4:
            recent = wrong_guesses[-4:]
            spread = max(recent) - min(recent)
            if spread < 20:
                return True, "spread", "💡 Hint: Try exploring a completely different area!"
        
        return False, None, None
    
    @classmethod
    def get_temperature(cls, guess, secret, max_range):
        diff = abs(guess - secret)
        percentage = diff / max_range if max_range else 0
        
        if percentage == 0:
            return "correct", "🎯 Correct!"
        elif percentage <= 0.05:
            return "hot", "🔥 SCALDING HOT!"
        elif percentage <= 0.10:
            return "hot", "🔥 Very Hot!"
        elif percentage <= 0.20:
            return "warm", "♨️ Warm!"
        elif percentage <= 0.35:
            return "warm", "😶 Lukewarm"
        else:
            return "cold", "❄️ Cold"
    
    @classmethod
    def get_hint(cls, session_data, guess, secret, max_range, difficulty):
        history = session_data.get("guess_history", [])
        hints_used = session_data.get("hints_used", 0)
        max_hints = cls.HINT_LIMITS[difficulty]
        
        temp_type, temp_msg = cls.get_temperature(guess, secret, max_range)
        
        should_hint, hint_type, hint_msg = cls.analyze_guess_history(history, secret, difficulty)
        
        if should_hint and hints_used < max_hints:
            hints_used += 1
            session_data["hints_used"] = hints_used
            session_data["hints_remaining"] = max_hints - hints_used
            return f"{temp_msg} | {hint_msg}", temp_type, session_data
        
        session_data["hints_remaining"] = max_hints - hints_used
        return temp_msg, temp_type, session_data

# =========================
# AUTH ROUTE
# =========================
@app.route("/", methods=["GET", "POST"])
def auth():
    session = get_session()
    
    if session.get("auth_complete"):
        response = make_response(redirect(url_for("calculator")))
        return save_session(response, session)
    
    error = None
    step = session.get("auth_step", "name")
    name = session.get("name")
    age_verified = session.get("age_verified")
    is_student = session.get("is_student")
    
    if request.method == "POST":
        form_step = request.form.get("step")
        logger.info(f"Auth step: {form_step}")
        
        if form_step == "name":
            name_input = request.form.get("name", "").strip()
            if name_input and 2 <= len(name_input) <= 50:
                session["name"] = name_input.title()
                session["auth_step"] = "age"
                response = make_response(redirect(url_for("auth")))
                return save_session(response, session)
            error = "Enter a valid name (2-50 characters)"
        
        elif form_step == "age":
            age_input = request.form.get("age", "").strip()
            if age_input.isdigit():
                age = int(age_input)
                if 15 <= age <= 129:
                    session["age_verified"] = True
                    session["age"] = age
                    session["auth_step"] = "student"
                    response = make_response(redirect(url_for("auth")))
                    return save_session(response, session)
                elif age < 15:
                    response = make_response(render_template("index.html", step="blocked", error="You must be at least 15 years old."))
                    return save_session(response, {})
            error = "Enter a valid age (15-129)"
        
        elif form_step == "student":
            identity = request.form.get("identity", "").lower().strip()
            if identity in ("y", "yes"):
                session["is_student"] = True
                session["auth_step"] = "passcode"
                response = make_response(redirect(url_for("auth")))
                return save_session(response, session)
            response = make_response(render_template("index.html", step="blocked", error="Access denied. Students only."))
            return save_session(response, {})
        
        elif form_step == "passcode":
            code = request.form.get("code", "")
            verify = request.form.get("verify", "")
            
            if (len(code) == 4 and code.isdigit() and 
                code == verify and code not in ("0000", "1234")):
                session["passcode"] = code
                session["auth_complete"] = True
                session["auth_step"] = "calculator"
                response = make_response(redirect(url_for("calculator")))
                return save_session(response, session)
            error = "Invalid passcode. Must be 4 digits, matching, not 0000/1234."
    
    # Determine step
    if not name:
        step = "name"
    elif not age_verified:
        step = "age"
    elif not is_student:
        step = "student"
    else:
        step = "passcode"
    
    session["auth_step"] = step
    response = make_response(render_template("index.html", step=step, name=name, error=error))
    return save_session(response, session)

# =========================
# CALCULATOR
# =========================
@app.route("/calculator")
@login_required
def calculator():
    session = get_session()
    response = make_response(render_template("index.html", step="calculator", name=session.get("name")))
    return save_session(response, session)

@app.route("/calculate", methods=["POST"])
@login_required
def calculate():
    session = get_session()
    data = request.get_json(silent=True) or {}
    
    expr = data.get("expression", "").strip()
    passcode = session.get("passcode", "")
    
    if expr == passcode:
        return jsonify({"action": "secret"})
    
    if not expr:
        return jsonify({"result": "0"})
    
    result = safe_calculate(expr)
    return jsonify({"result": str(result)})

# =========================
# GAME SYSTEM
# =========================
@app.route("/game/new", methods=["POST"])
@login_required
def new_game():
    session = get_session()
    data = request.get_json(silent=True) or {}
    difficulty = data.get("difficulty", "Easy")
    
    settings = {
        "Easy": (50, 10),
        "Medium": (100, 7),
        "Hard": (200, 5),
        "Nightmare": (500, 5)
    }
    
    max_range, attempts = settings.get(difficulty, settings["Easy"])
    secret = random.randint(1, max_range)
    
    session["secret_number"] = secret
    session["attempts"] = attempts
    session["max_range"] = max_range
    session["difficulty"] = difficulty
    session["guess_history"] = []
    session["hints_used"] = 0
    session["hints_remaining"] = AdaptiveHintSystem.HINT_LIMITS[difficulty]
    
    response = make_response(jsonify({
        "attempts": attempts,
        "range": max_range,
        "hint": "Game started! Enter your first guess.",
        "hints_available": session["hints_remaining"],
        "difficulty": difficulty
    }))
    return save_session(response, session)

@app.route("/game/guess", methods=["POST"])
@login_required
def guess():
    session = get_session()
    data = request.get_json(silent=True) or {}
    
    try:
        guess_num = int(data.get("guess", 0))
    except (ValueError, TypeError):
        return jsonify({"result": "invalid", "message": "Please enter a valid number"})
    
    secret = session.get("secret_number")
    attempts = session.get("attempts", 0)
    max_range = session.get("max_range", 100)
    difficulty = session.get("difficulty", "Easy")
    history = session.get("guess_history", [])
    
    if not (1 <= guess_num <= max_range):
        return jsonify({"result": "outofrange", "max_range": max_range, "message": f"Number must be between 1 and {max_range}"})
    
    history.append(guess_num)
    session["guess_history"] = history
    
    if attempts <= 0:
        return jsonify({"result": "gameover", "number": secret, "message": f"💀 Game Over! The number was {secret}"})
    
    if guess_num == secret:
        return jsonify({
            "result": "correct",
            "number": secret,
            "guesses_used": len(history),
            "hints_used": session.get("hints_used", 0),
            "message": f"🎉 Correct! The number was {secret}!"
        })
    
    session["attempts"] = attempts - 1
    
    hint_msg, temp_type, updated_session = AdaptiveHintSystem.get_hint(
        session, guess_num, secret, max_range, difficulty
    )
    session.update(updated_session)
    
    remaining = session["attempts"]
    hints_left = session.get("hints_remaining", 0)
    
    response_data = {
        "result": "wrong",
        "attempts": remaining,
        "hint": hint_msg,
        "temperature": temp_type,
        "hints_remaining": hints_left,
        "guesses_so_far": len(history)
    }
    
    if remaining <= 2 and hints_left > 0 and difficulty != "Nightmare":
        diff = abs(guess_num - secret)
        direction = "higher" if guess_num < secret else "lower"
        response_data["panic_hint"] = f"⚠️ Only {remaining} left! Try {direction}."
        session["hints_used"] = session.get("hints_used", 0) + 1
        session["hints_remaining"] = max(0, hints_left - 1)
    
    response = make_response(jsonify(response_data))
    return save_session(response, session)

# =========================
# LOGOUT
# =========================
@app.route("/logout")
def logout():
    response = make_response(redirect(url_for("auth")))
    # Clear session by setting empty cookie
    response.set_cookie('session', '', expires=0, httponly=True, secure=True, samesite='Strict')
    return response

# =========================
# HEALTH CHECK (CRITICAL FOR VERCEL)
# =========================
@app.route("/health")
def health():
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat() + "Z"})

# =========================
# ERROR HANDLERS
# =========================
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"500 error: {str(e)}", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500
