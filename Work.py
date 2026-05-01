from flask import Flask, render_template, request, session, redirect, url_for, jsonify
import random
import os
import ast
import operator
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

# Safe math evaluation
ALLOWED_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

def safe_eval(node):
    if isinstance(node, ast.Num) or isinstance(node, ast.Constant):
        return node.n if hasattr(node, 'n') else node.value
    elif isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in ALLOWED_OPS:
            raise ValueError(f"Unsupported operation: {op_type}")
        return ALLOWED_OPS[op_type](safe_eval(node.left), safe_eval(node.right))
    elif isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in ALLOWED_OPS:
            raise ValueError(f"Unsupported unary operation: {op_type}")
        return ALLOWED_OPS[op_type](safe_eval(node.operand))
    raise ValueError("Unsupported expression")

def evaluate_expression(expr):
    try:
        tree = ast.parse(expr, mode='eval')
        return safe_eval(tree.body)
    except Exception as e:
        raise ValueError(f"Invalid expression: {str(e)}")

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("auth_complete"):
            return redirect(url_for("auth"))
        return f(*args, **kwargs)
    return decorated_function

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
        step = request.form.get("step")

        if step == "name":
            name_input = request.form.get("name", "").strip()
            if not name_input:
                error = "Name cannot be empty"
            elif not name_input.replace(" ", "").isalpha():
                error = "Name can only contain letters and spaces"
            elif len(name_input) > 50:
                error = "Name too long (max 50 characters)"
            else:
                session["name"] = name_input.title()
                return redirect(url_for("auth"))

        elif step == "age":
            age_input = request.form.get("age", "").strip()
            if not age_input:
                error = "Please enter your age"
            elif not age_input.isdigit():
                error = "Age must be a number"
            else:
                age = int(age_input)
                if age >= 130:
                    error = "You cannot possibly be older than 129"
                elif age <= 14:
                    error = "You must be 15 or older to use this program"
                    session.clear()
                    return render_template("index.html", step="blocked", error=error)
                else:
                    session["age_verified"] = True
                    return redirect(url_for("auth"))

        elif step == "student":
            identity = request.form.get("identity", "").strip().lower()
            if identity == "n":
                error = "This calculator is designed for students. Access denied."
                session.clear()
                return render_template("index.html", step="blocked", error=error)
            elif identity == "y":
                session["is_student"] = True
                return redirect(url_for("auth"))
            else:
                error = "Please enter Y for yes or n for no"

        elif step == "passcode":
            code = request.form.get("code", "").strip()
            verify = request.form.get("verify", "").strip()
            if len(code) != 4 or not code.isdigit():
                error = "Passcode must be exactly 4 digits"
            elif code != verify:
                error = "Passcodes do not match"
            elif code == "0000":
                error = "Passcode too weak"
            else:
                session["passcode"] = code
                session["auth_complete"] = True
                return redirect(url_for("calculator"))

    if not name:
        step = "name"
    elif not age_verified:
        step = "age"
    elif not is_student:
        step = "student"
    else:
        step = "passcode"

    return render_template("index.html", step=step, name=name, error=error)

@app.route("/calculator")
@login_required
def calculator():
    return render_template("index.html", step="calculator", name=session.get("name"))

@app.route("/calculate", methods=["POST"])
@login_required
def calculate():
    data = request.get_json()
    expression = data.get("expression", "").strip()
    passcode = session.get("passcode", "")

    if expression == passcode:
        return jsonify({"action": "secret"})

    if not expression:
        return jsonify({"result": "0"})

    try:
        result = evaluate_expression(expression)
        if isinstance(result, float):
            if result.is_integer():
                result = int(result)
            else:
                result = round(result, 10)
        return jsonify({"result": str(result)})
    except ZeroDivisionError:
        return jsonify({"result": "Error: ÷0"})
    except Exception as e:
        return jsonify({"result": "Error"})

@app.route("/game/new", methods=["POST"])
@login_required
def new_game():
    data = request.get_json()
    difficulty = data.get("difficulty", "Easy")
    
    settings = {
        "Easy": {"range": 50, "attempts": 10, "hint": "Hot/Warm/Cold enabled"},
        "Medium": {"range": 100, "attempts": 7, "hint": "Hot/Warm/Cold enabled"},
        "Hard": {"range": 200, "attempts": 5, "hint": "Hot/Warm/Cold enabled"},
        "Nightmare": {"range": 500, "attempts": 5, "hint": "No hints, pure instinct"}
    }
    
    selected = settings.get(difficulty, settings["Easy"])
    secret_number = random.randint(1, selected["range"])
    
    session["secret_number"] = secret_number
    session["attempts"] = selected["attempts"]
    session["max_range"] = selected["range"]
    session["difficulty"] = difficulty
    session["hints_enabled"] = difficulty != "Nightmare"
    
    return jsonify({
        "attempts": selected["attempts"], 
        "range": selected["range"],
        "hint": selected["hint"]
    })

@app.route("/game/guess", methods=["POST"])
@login_required
def guess():
    data = request.get_json()
    guess_input = data.get("guess", "").strip()
    
    try:
        guess_val = int(guess_input)
    except (ValueError, TypeError):
        return jsonify({"result": "invalid"})

    secret = session.get("secret_number")
    attempts = session.get("attempts", 0)
    max_range = session.get("max_range", 50)
    hints_enabled = session.get("hints_enabled", True)

    if attempts <= 0:
        return jsonify({"result": "gameover", "number": secret})

    if guess_val < 1 or guess_val > max_range:
        return jsonify({"result": "outofrange", "max_range": max_range})

    difference = abs(guess_val - secret)

    if guess_val == secret:
        session["attempts"] = 0
        return jsonify({"result": "correct", "number": secret})

    attempts -= 1
    session["attempts"] = attempts

    if hints_enabled:
        if difference <= 3:
            hint = "HOT 🔥"
        elif difference <= 10:
            hint = "WARM 🌤"
        else:
            hint = "COLD ❄"
    else:
        hint = "Keep trying..."

    if attempts <= 0:
        return jsonify({"result": "gameover", "number": secret})

    return jsonify({"result": "wrong", "hint": hint, "attempts": attempts})

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
