from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import random
import os
from functools import wraps
import logging

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

# =========================
# LOGGING SETUP
# =========================
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

@app.before_request
def log_request_info():
    logger.info(f"{request.method} {request.path}")


# =========================
# AUTH DECORATOR
# =========================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("auth_complete"):
            logger.warning("Unauthorized access attempt")
            return redirect(url_for("auth"))
        return f(*args, **kwargs)
    return decorated_function


# =========================
# SAFE CALCULATOR
# =========================
def safe_calculate(expr: str):
    allowed_chars = "0123456789+-*/().% "

    logger.debug(f"Evaluating: {expr}")

    if any(c not in allowed_chars for c in expr):
        logger.warning("Invalid characters in expression")
        return "Error"

    try:
        result = eval(expr, {"__builtins__": None}, {})
        return result
    except Exception as e:
        logger.error(f"Calculation error: {expr} | {e}")
        return "Error"


# =========================
# AUTH ROUTE
# =========================
@app.route("/", methods=["GET", "POST"])
def auth():
    if session.get("auth_complete"):
        return redirect(url_for("calculator"))

    error = None
    step = "name"
    name = session.get("name")
    age_verified = session.get("age_verified")
    is_student = session.get("is_student")

    if request.method == "POST":
        logger.debug(f"Auth step data: {request.form}")

        step = request.form.get("step")

        if step == "name":
            name_input = request.form.get("name", "").strip()
            if name_input:
                session["name"] = name_input.title()
                return redirect(url_for("auth"))
            error = "Enter a valid name"

        elif step == "age":
            age_input = request.form.get("age", "").strip()
            if age_input.isdigit():
                age = int(age_input)
                if age <= 14:
                    logger.warning("User blocked due to age")
                    session.clear()
                    return render_template("index.html", step="blocked", error="Too young")
                session["age_verified"] = True
                return redirect(url_for("auth"))
            error = "Invalid age"

        elif step == "student":
            identity = request.form.get("identity", "").lower()
            if identity == "y":
                session["is_student"] = True
                return redirect(url_for("auth"))
            logger.warning("User failed student check")
            session.clear()
            return render_template("index.html", step="blocked", error="Access denied")

        elif step == "passcode":
            code = request.form.get("code", "")
            verify = request.form.get("verify", "")

            if len(code) == 4 and code == verify and code != "0000":
                session["passcode"] = code
                session["auth_complete"] = True
                logger.info("User authentication complete")
                return redirect(url_for("calculator"))

            error = "Invalid passcode"

    if not name:
        step = "name"
    elif not age_verified:
        step = "age"
    elif not is_student:
        step = "student"
    else:
        step = "passcode"

    return render_template("index.html", step=step, name=name, error=error)


# =========================
# CALCULATOR PAGE
# =========================
@app.route("/calculator")
@login_required
def calculator():
    logger.info("User accessed calculator")
    return render_template("index.html", step="calculator", name=session.get("name"))


# =========================
# CALCULATE API
# =========================
@app.route("/calculate", methods=["POST"])
@login_required
def calculate():
    data = request.get_json(silent=True)
    logger.debug(f"Incoming JSON: {data}")

    if not data or "expression" not in data:
        logger.warning("Invalid request to /calculate")
        return jsonify({"result": "Error"})

    expr = data["expression"].strip()
    logger.info(f"Expression: {expr}")

    passcode = session.get("passcode", "")

    if expr == passcode:
        logger.info("Secret feature triggered")
        return jsonify({"action": "secret"})

    if expr == "":
        return jsonify({"result": "0"})

    result = safe_calculate(expr)
    logger.info(f"Result: {result}")

    return jsonify({"result": str(result)})


# =========================
# GAME SYSTEM
# =========================
@app.route("/game/new", methods=["POST"])
@login_required
def new_game():
    data = request.get_json()
    difficulty = data.get("difficulty", "Easy")

    logger.info(f"New game started: {difficulty}")

    settings = {
        "Easy": (50, 10),
        "Medium": (100, 7),
        "Hard": (200, 5),
        "Nightmare": (500, 5)
    }

    max_range, attempts = settings.get(difficulty, settings["Easy"])

    session["secret_number"] = random.randint(1, max_range)
    session["attempts"] = attempts
    session["max_range"] = max_range
    session["hints_enabled"] = difficulty != "Nightmare"

    return jsonify({
        "attempts": attempts,
        "range": max_range,
        "hint": "Game started"
    })


@app.route("/game/guess", methods=["POST"])
@login_required
def guess():
    data = request.get_json()
    guess_val = int(data.get("guess", 0))

    secret = session.get("secret_number")
    attempts = session.get("attempts", 0)

    logger.info(f"Guess: {guess_val}, Secret: {secret}, Attempts: {attempts}")

    if attempts <= 0:
        return jsonify({"result": "gameover", "number": secret})

    if guess_val == secret:
        return jsonify({"result": "correct", "number": secret})

    session["attempts"] -= 1

    return jsonify({
        "result": "wrong",
        "attempts": session["attempts"]
    })


# =========================
# LOGOUT
# =========================
@app.route("/logout")
def logout():
    logger.info("User logged out")
    session.clear()
    return redirect(url_for("auth"))


# =========================
# ENTRY POINT
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
