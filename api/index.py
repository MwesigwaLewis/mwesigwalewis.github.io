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
from werkzeug.utils import secure_filename

# =========================
# VERCEL-SPECIFIC CONFIG
# =========================
app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable is required")

# Disable Flask's default server header for security
app.config['SERVER_NAME'] = None
app.config['PREFERRED_URL_SCHEME'] = 'https'

# =========================
# ENTERPRISE-GRADE LOGGING
# =========================
class JSONFormatter(logging.Formatter):
    """Structured JSON logging for Vercel log ingestion"""
    def format(self, record):
        log_obj = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "path": getattr(record, "path", None),
            "method": getattr(record, "method", None),
            "ip": getattr(record, "ip", None),
            "user": getattr(record, "user", None),
            "game_id": getattr(record, "game_id", None),
            "session_step": getattr(record, "session_step", None)
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj, default=str)

# Configure root logger for Vercel's log capture
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JSONFormatter())
app.logger.handlers = []
app.logger.addHandler(handler)
app.logger.setLevel(logging.DEBUG)

# Also capture Werkzeug logs
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.handlers = [handler]
werkzeug_logger.setLevel(logging.INFO)

logger = app.logger

# =========================
# STATELESS SESSION SYSTEM (Vercel-Compatible)
# =========================
class SecureCookieSession:
    """
    Server-side encrypted session using signed cookies.
    Vercel Functions are stateless — this persists state client-side 
    but cryptographically verified server-side.
    """
    def __init__(self, secret_key):
        self.secret = secret_key.encode()
    
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
    """Retrieve session from secure cookie"""
    cookie = request.cookies.get('session', '')
    return session_manager.decode(cookie)

def save_session(response, data):
    """Save session to secure cookie"""
    encoded = session_manager.encode(data)
    response.set_cookie(
        'session', encoded,
        httponly=True,
        secure=True,
        samesite='Strict',
        max_age=3600  # 1 hour
    )
    return response

def update_session(data):
    """Helper to update session and return response wrapper"""
    def decorator(response):
        return save_session(response, data)
    return decorator

# =========================
# REQUEST LOGGING MIDDLEWARE
# =========================
@app.before_request
def log_request_info():
    session = get_session()
    extra = {
        "path": request.path,
        "method": request.method,
        "ip": request.headers.get('X-Forwarded-For', request.remote_addr),
        "user": session.get("name", "anonymous"),
        "session_step": session.get("auth_step", "unknown")
    }
    logger.info(f"→ {request.method} {request.path} | User: {extra['user']} | Step: {extra['session_step']}", extra=extra)

@app.after_request
def log_response_info(response):
    session = get_session()
    extra = {
        "path": request.path,
        "method": request.method,
        "status": response.status_code,
        "user": session.get("name", "anonymous")
    }
    logger.info(f"← {response.status_code} {request.path} | User: {extra['user']}", extra=extra)
    return response

# =========================
# AUTH DECORATOR
# =========================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session = get_session()
        if not session.get("auth_complete"):
            logger.warning("Unauthorized access attempt", extra={
                "path": request.path,
                "ip": request.headers.get('X-Forwarded-For', request.remote_addr)
            })
            response = make_response(redirect(url_for("auth")))
            return save_session(response, session)
        return f(*args, **kwargs)
    return decorated_function

# =========================
# SAFE CALCULATOR
# =========================
def safe_calculate(expr: str):
    allowed_chars = set("0123456789+-*/().% ")
    logger.debug(f"Evaluating expression: {expr}")
    
    if not expr or any(c not in allowed_chars for c in expr):
        logger.warning(f"Invalid characters in expression: {expr}")
        return "Error"
    
    # Prevent empty/whitespace-only expressions from evaluating
    if not expr.strip():
        return "0"
    
    try:
        # Additional safety: limit length
        if len(expr) > 200:
            logger.warning("Expression too long")
            return "Error"
        result = eval(expr, {"__builtins__": None}, {})
        logger.info(f"Calculation successful: {expr} = {result}")
        return result
    except Exception as e:
        logger.error(f"Calculation error: {expr} | {type(e).__name__}: {e}")
        return "Error"

# =========================
# INTELLIGENT HINT SYSTEM
# =========================
class AdaptiveHintSystem:
    """
    Smart hint system that adapts to player performance:
    - Tracks guess patterns (high/low oscillation, clustering)
    - Provides directional hints when player is struggling
    - Limits hints based on difficulty and performance
    - Hot/Warm/Cold temperature feedback
    """
    
    # Hint limits per difficulty
    HINT_LIMITS = {
        "Easy": 5,
        "Medium": 3,
        "Hard": 2,
        "Nightmare": 0  # No hints in Nightmare
    }
    
    # Performance thresholds (wrong guesses before hint offered)
    THRESHOLDS = {
        "Easy": 3,
        "Medium": 4,
        "Hard": 5,
        "Nightmare": float('inf')
    }
    
    @classmethod
    def analyze_guess_history(cls, history, secret, difficulty):
        """
        Analyze guess patterns to determine if player needs help.
        Returns: (should_offer_hint, hint_type, hint_message)
        """
        if difficulty == "Nightmare":
            return False, None, None
        
        if not history:
            return False, None, None
        
        wrong_guesses = [g for g in history if g != secret]
        if len(wrong_guesses) < cls.THRESHOLDS[difficulty]:
            return False, None, None
        
        # Check for oscillation pattern (going back and forth)
        if len(wrong_guesses) >= 3:
            recent = wrong_guesses[-3:]
            directions = []
            for g in recent:
                if g < secret:
                    directions.append("low")
                else:
                    directions.append("high")
            
            # If oscillating between high/low, player is confused
            if len(set(directions)) > 1 and len(directions) >= 3:
                return True, "direction", "💡 Hint: You're oscillating! Pick a number in the middle of your last two guesses."
            
            # If consistently wrong direction multiple times
            if len(set(directions)) == 1:
                direction = "higher" if directions[0] == "low" else "lower"
                return True, "direction", f"💡 Hint: The number is {direction} than your recent guesses."
        
        # Check for clustering (stuck in same area)
        if len(wrong_guesses) >= 4:
            recent = wrong_guesses[-4:]
            spread = max(recent) - min(recent)
            range_size = max(secret * 2, 50)  # Approximate range
            if spread < range_size * 0.15:  # Clustered in <15% of range
                return True, "spread", "💡 Hint: Try exploring a different area of the range!"
        
        return False, None, None
    
    @classmethod
    def get_temperature_hint(cls, guess, secret, max_range):
        """Get temperature-based feedback (always provided)"""
        diff = abs(guess - secret)
        percentage = diff / max_range
        
        if percentage == 0:
            return "correct", "🎯 Correct!"
        elif percentage <= 0.05:
            return "hot", "🔥 SCALDING HOT! Within 5%!"
        elif percentage <= 0.10:
            return "hot", "🔥 Very Hot! Within 10%!"
        elif percentage <= 0.20:
            return "warm", "♨️ Warm! Within 20%."
        elif percentage <= 0.35:
            return "warm", "😶 Lukewarm. Getting closer."
        else:
            return "cold", "❄️ Cold. Far away."
    
    @classmethod
    def get_numerical_hint(cls, guess, secret, hints_used, max_hints, difficulty):
        """
        Provide numerical proximity hint when player is struggling.
        Only reveals range information, never the exact number.
        """
        if hints_used >= max_hints:
            return None
        
        diff = abs(guess - secret)
        
        # Progressive hint revelation
        if hints_used == 0:
            # First hint: reveal if within factor of 2
            if diff <= secret * 0.5:
                return "💡 The number is within 50% of your last guess."
            else:
                return "💡 The number is more than 50% away from your last guess."
        elif hints_used == 1:
            # Second hint: quarter-range info
            quarter = max_range // 4
            secret_quarter = (secret - 1) // quarter
            return f"💡 The number is in quarter {secret_quarter + 1} of the range."
        else:
            # Final hints: narrower range
            lower = max(1, secret - diff // 2)
            upper = min(max_range, secret + diff // 2)
            return f"💡 The number is between {lower} and {upper}."
    
    @classmethod
    def get_hint(cls, session_data, guess, secret, max_range, difficulty):
        """
        Main hint generation logic. Returns (hint_message, hint_type, updated_session)
        """
        history = session_data.get("guess_history", [])
        hints_used = session_data.get("hints_used", 0)
        max_hints = cls.HINT_LIMITS[difficulty]
        
        # Always get temperature feedback
        temp_type, temp_msg = cls.get_temperature_hint(guess, secret, max_range)
        
        # Check if we should offer an intelligent hint
        should_hint, hint_type, hint_msg = cls.analyze_guess_history(history, secret, difficulty)
        
        if should_hint and hints_used < max_hints:
            # Generate specific numerical hint
            numerical_hint = cls.get_numerical_hint(guess, secret, hints_used, max_hints, difficulty)
            if numerical_hint:
                hints_used += 1
                session_data["hints_used"] = hints_used
                session_data["hints_remaining"] = max_hints - hints_used
                return f"{temp_msg} | {numerical_hint}", temp_type, session_data
        
        # Just return temperature feedback
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
        logger.info(f"Auth step submission: {form_step}", extra={
            "user": name or "unknown",
            "session_step": step
        })
        
        if form_step == "name":
            name_input = request.form.get("name", "").strip()
            if name_input and len(name_input) >= 2 and len(name_input) <= 50:
                session["name"] = secure_filename(name_input).replace('_', ' ').title()
                session["auth_step"] = "age"
                logger.info(f"Name set: {session['name']}", extra={"user": session["name"]})
                response = make_response(redirect(url_for("auth")))
                return save_session(response, session)
            error = "Enter a valid name (2-50 characters)"
            logger.warning("Invalid name input", extra={"input": name_input})
        
        elif form_step == "age":
            age_input = request.form.get("age", "").strip()
            if age_input.isdigit():
                age = int(age_input)
                if 15 <= age <= 129:
                    session["age_verified"] = True
                    session["age"] = age
                    session["auth_step"] = "student"
                    logger.info(f"Age verified: {age}", extra={"user": session.get("name")})
                    response = make_response(redirect(url_for("auth")))
                    return save_session(response, session)
                elif age < 15:
                    logger.warning(f"Underage user blocked: {age}", extra={"user": session.get("name")})
                    session.clear()
                    response = make_response(render_template("index.html", step="blocked", error="You must be at least 15 years old to use this tool."))
                    return save_session(response, {})
            error = "Enter a valid age (15-129)"
            logger.warning("Invalid age input", extra={"input": age_input})
        
        elif form_step == "student":
            identity = request.form.get("identity", "").lower().strip()
            if identity in ("y", "yes"):
                session["is_student"] = True
                session["auth_step"] = "passcode"
                logger.info("Student verified", extra={"user": session.get("name")})
                response = make_response(redirect(url_for("auth")))
                return save_session(response, session)
            logger.warning("Non-student access denied", extra={"user": session.get("name"), "response": identity})
            session.clear()
            response = make_response(render_template("index.html", step="blocked", error="Access denied. This tool is for students only."))
            return save_session(response, {})
        
        elif form_step == "passcode":
            code = request.form.get("code", "")
            verify = request.form.get("verify", "")
            
            if (len(code) == 4 and code.isdigit() and 
                code == verify and code != "0000" and code != "1234"):
                session["passcode"] = code
                session["auth_complete"] = True
                session["auth_step"] = "calculator"
                logger.info("Authentication complete", extra={"user": session.get("name")})
                response = make_response(redirect(url_for("calculator")))
                return save_session(response, session)
            
            error = "Invalid passcode. Must be 4 digits, matching, and not 0000/1234."
            logger.warning("Passcode validation failed", extra={"user": session.get("name")})
    
    # Determine current step
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
# CALCULATOR PAGE
# =========================
@app.route("/calculator")
@login_required
def calculator():
    session = get_session()
    logger.info("Calculator accessed", extra={"user": session.get("name")})
    response = make_response(render_template("index.html", step="calculator", name=session.get("name")))
    return save_session(response, session)

# =========================
# CALCULATE API
# =========================
@app.route("/calculate", methods=["POST"])
@login_required
def calculate():
    session = get_session()
    data = request.get_json(silent=True)
    logger.debug(f"Calculate request: {data}", extra={"user": session.get("name")})
    
    if not data or "expression" not in data:
        logger.warning("Invalid calculate request", extra={"user": session.get("name")})
        return jsonify({"result": "Error"})
    
    expr = data["expression"].strip()
    passcode = session.get("passcode", "")
    
    # Secret feature trigger
    if expr == passcode:
        logger.info("Secret game unlocked", extra={"user": session.get("name")})
        return jsonify({"action": "secret"})
    
    if not expr:
        return jsonify({"result": "0"})
    
    result = safe_calculate(expr)
    logger.info(f"Calculation: {expr} = {result}", extra={"user": session.get("name")})
    return jsonify({"result": str(result)})

# =========================
# GAME SYSTEM WITH ADAPTIVE HINTS
# =========================
@app.route("/game/new", methods=["POST"])
@login_required
def new_game():
    session = get_session()
    data = request.get_json(silent=True) or {}
    difficulty = data.get("difficulty", "Easy")
    
    logger.info(f"New game started: {difficulty}", extra={
        "user": session.get("name"),
        "game_id": id(session)
    })
    
    settings = {
        "Easy": (50, 10),
        "Medium": (100, 7),
        "Hard": (200, 5),
        "Nightmare": (500, 5)
    }
    
    max_range, attempts = settings.get(difficulty, settings["Easy"])
    secret = random.randint(1, max_range)
    
    # Initialize game state
    session["secret_number"] = secret
    session["attempts"] = attempts
    session["max_range"] = max_range
    session["difficulty"] = difficulty
    session["guess_history"] = []
    session["hints_used"] = 0
    session["hints_remaining"] = AdaptiveHintSystem.HINT_LIMITS[difficulty]
    session["game_start_time"] = datetime.utcnow().isoformat()
    
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
    
    guess_val = data.get("guess")
    secret = session.get("secret_number")
    attempts = session.get("attempts", 0)
    max_range = session.get("max_range", 100)
    difficulty = session.get("difficulty", "Easy")
    history = session.get("guess_history", [])
    
    # Validate input
    try:
        guess_num = int(guess_val) if guess_val is not None else None
    except (ValueError, TypeError):
        logger.warning("Invalid guess format", extra={
            "user": session.get("name"),
            "guess": guess_val
        })
        return jsonify({"result": "invalid", "message": "Please enter a valid number"})
    
    if guess_num is None:
        return jsonify({"result": "invalid", "message": "Please enter a number"})
    
    # Validate range
    if not (1 <= guess_num <= max_range):
        logger.info(f"Out of range guess: {guess_num} (range: 1-{max_range})", extra={
            "user": session.get("name")
        })
        return jsonify({
            "result": "outofrange",
            "max_range": max_range,
            "message": f"Number must be between 1 and {max_range}"
        })
    
    # Record guess
    history.append(guess_num)
    session["guess_history"] = history
    
    logger.info(f"Guess: {guess_num} | Secret: {secret} | Attempts left: {attempts}", extra={
        "user": session.get("name"),
        "game_id": id(session),
        "guess": guess_num,
        "secret": secret,
        "attempts_remaining": attempts
    })
    
    # Check game over
    if attempts <= 0:
        logger.info(f"Game over. Secret was {secret}", extra={"user": session.get("name")})
        response = make_response(jsonify({
            "result": "gameover",
            "number": secret,
            "message": f"💀 Game Over! The number was {secret}"
        }))
        return save_session(response, session)
    
    # Check correct
    if guess_num == secret:
        guesses_count = len(history)
        logger.info(f"Game won! {guesses_count} guesses used", extra={
            "user": session.get("name"),
            "guesses": guesses_count
        })
        response = make_response(jsonify({
            "result": "correct",
            "number": secret,
            "guesses_used": guesses_count,
            "hints_used": session.get("hints_used", 0),
            "message": f"🎉 Correct! The number was {secret}!"
        }))
        return save_session(response, session)
    
    # Wrong guess - decrement attempts
    session["attempts"] = attempts - 1
    
    # Get adaptive hint
    hint_msg, temp_type, updated_session = AdaptiveHintSystem.get_hint(
        session, guess_num, secret, max_range, difficulty
    )
    session.update(updated_session)
    
    # Build response
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
    
    # Add panic hint if critically low on attempts
    if remaining <= 2 and hints_left > 0 and difficulty != "Nightmare":
        diff = abs(guess_num - secret)
        direction = "higher" if guess_num < secret else "lower"
        response_data["panic_hint"] = f"⚠️ Only {remaining} attempts left! Try something {direction}."
        session["hints_used"] = session.get("hints_used", 0) + 1
        session["hints_remaining"] = max(0, hints_left - 1)
    
    logger.info(f"Wrong guess. Attempts left: {remaining} | Hint: {temp_type}", extra={
        "user": session.get("name"),
        "temperature": temp_type,
        "hints_remaining": session.get("hints_remaining", 0)
    })
    
    response = make_response(jsonify(response_data))
    return save_session(response, session)

# =========================
# GAME STATS (Bonus Endpoint)
# =========================
@app.route("/game/stats", methods=["GET"])
@login_required
def game_stats():
    session = get_session()
    history = session.get("guess_history", [])
    secret = session.get("secret_number")
    
    if not secret:
        return jsonify({"error": "No active game"})
    
    stats = {
        "total_guesses": len(history),
        "attempts_remaining": session.get("attempts", 0),
        "hints_used": session.get("hints_used", 0),
        "hints_remaining": session.get("hints_remaining", 0),
        "difficulty": session.get("difficulty"),
        "guess_history": history,
        "performance_score": max(0, 100 - len(history) * 5 + session.get("hints_remaining", 0) * 10)
    }
    
    return jsonify(stats)

# =========================
# LOGOUT
# =========================
@app.route("/logout")
def logout():
    session = get_session()
    logger.info("User logged out", extra={"user": session.get("name")})
    response = make_response(redirect(url_for("auth")))
    return save_session(response, {})

# =========================
# HEALTH CHECK (Vercel)
# =========================
@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "version": "2.0.0"
    })

# =========================
# ERROR HANDLERS
# =========================
@app.errorhandler(404)
def not_found(e):
    logger.warning(f"404: {request.path}")
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"500 error: {str(e)}", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500
