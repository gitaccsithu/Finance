import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    U_info = []  # create array for index
    g_total = 0.0

    shares_rows = db.execute("SELECT symbol, SUM(shares) FROM history GROUP BY symbol HAVING user_id = ?", int(session["user_id"]))
    user_rows = db.execute("SELECT cash FROM users WHERE id = ?", int(session["user_id"]))

    for row in shares_rows:
        dic = {}
        if row["SUM(shares)"] > 0:
            dic["symbol"] = row["symbol"]
            dic["name"] = lookup(row["symbol"])["name"]
            dic["shares"] = int(row["SUM(shares)"])
            dic["price"] = usd(lookup(row["symbol"])["price"])
            dic["total"] = usd(lookup(row["symbol"])["price"] * float(row["SUM(shares)"]))
            g_total += lookup(row["symbol"])["price"] * float(row["SUM(shares)"])

        U_info.append(dic)

    g_total += float(user_rows[0]["cash"])
    print(g_total)

    return render_template("index.html", Uinfo=U_info, Ucash=usd(user_rows[0]["cash"]), gtotal=usd(g_total))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    if request.method == "POST":
        symbol = request.form.get("symbol")


        if not symbol:
            return apology("Input blank", 400)

        if lookup(symbol) == None:
            return apology("Symbol does not exit", 400)

        for word in request.form.get("shares").split():
            if not word.isdigit():
                return apology("Shares must be positive number")

        shares = int(request.form.get("shares"))
        if shares < 0:
            return apology("Shares must be positive number", 400)

        rows = db.execute('SELECT * FROM users WHERE id = ?', int(session["user_id"]))
        cost = shares * lookup(symbol)["price"]

        if cost > float(rows[0]["cash"]):
            return apology("Not enough cash", 400)

        purchase = db.execute("INSERT INTO history(user_id, symbol, shares, price, date_time) VALUES(?, ?, ?, ?, ?)",
                              int(session["user_id"]), symbol, shares, lookup(symbol)["price"], str(datetime.now()))
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   int(rows[0]["cash"]) - cost, int(session["user_id"]))

        flash("bought!")
        return redirect("/")


@app.route("/changepass", methods=["GET", "POST"])
@login_required
def changepass():

    if request.method == "GET":

        return render_template("changepass.html")

    if request.method == "POST":

        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        if not check_password_hash(rows[0]["hash"], request.form.get("old_pass")):
            return apology("Wrong old password")

        if len(request.form.get("new_pass")) < 6:
            return apology("Password must have six characters")

        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(
            request.form.get("new_pass"), method='pbkdf2:sha256', salt_length=8), int(session["user_id"]))

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    histories = db.execute("SELECT * FROM history WHERE user_id = ? ORDER BY id", int(session["user_id"]))

    return render_template("history.html", histories=histories)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":

        return render_template("quote.html")

    if request.method == "POST":

        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        if quote == None:
            return apology("Quote does not exit", 400)
        else:
            result = "A share of " + quote["name"] + ". (" + quote["symbol"] + ") costs " + usd(quote["price"])
            return render_template("quoted.html", result=result)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":

        return render_template("register.html")

    if request.method == "POST":

        U_name = request.form.get("username")

        if not U_name:
            return apology("Enter user name")

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if rows:
            return apology("Username already exit")

        U_pass = request.form.get("password")

        if not U_pass:
            return apology("Enter password")

        U_pass_confirm = request.form.get("confirmation")
        if U_pass != U_pass_confirm:
            return apology("Password do not match")

        if len(U_pass) < 6:
            return apology("Password must have six characters")

        U_pass_hashed = generate_password_hash(U_pass, method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users(username, hash) VALUES (?, ?)", U_name, U_pass_hashed)

        return redirect("/login")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    shares_rows = db.execute("SELECT symbol, SUM(shares) FROM history GROUP BY symbol HAVING user_id = ?", int(session["user_id"]))

    if request.method == "GET":

        return render_template("sell.html", symbols=shares_rows)

    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        rows = db.execute('SELECT * FROM users WHERE id = ?', int(session["user_id"]))

        if not symbol:
            return apology("Select symbol")

        if shares < 0:
            return apology("Share must be positive")

        if next(item for item in shares_rows if item["symbol"] == symbol)["SUM(shares)"] == 0:
            return apology("Not enough shares")

        if shares > next(item for item in shares_rows if item["symbol"] == symbol)["SUM(shares)"]:
            return apology("Not enough shares")

        sell = db.execute("INSERT INTO history(user_id, symbol, shares, price, date_time) VALUES(?, ?, ?, ?, ?)",
                          int(session["user_id"]), symbol, shares * (-1), lookup(symbol)["price"], str(datetime.now()))
        db.execute("UPDATE users SET cash = ? WHERE id = ?",
                   int(rows[0]["cash"]) + (lookup(symbol)["price"] * shares), int(session["user_id"]))

        flash("sold!")
        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
