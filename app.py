import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

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
    all_stocks = db.execute("SELECT symbol, SUM(shares) AS totalshares FROM data WHERE user_id = :user_id GROUP BY symbol HAVING totalshares > 0", user_id=session["user_id"])
    user = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
    store_stocks = {}
    total = 0
    for stock in all_stocks:
        store_stocks[stock["symbol"]] = lookup(stock["symbol"])
        total += lookup(stock["symbol"])["price"] * stock["totalshares"]

    cash = user[0]['cash']
    total += cash

    return render_template("index.html", cash=cash, store_stocks=store_stocks, all_stocks=all_stocks, total=total)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Missing symbol")

        if not request.form.get("shares"):
            return apology("Missing shares")

        if int(request.form.get("shares")) <= 0:
            return apology("Shares must be positive integer")

        stock = lookup(request.form.get("symbol"))

        if not stock:
            return apology("Invalid symbol")

        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        cash = rows[0]["cash"]
        pps = stock["price"]

        total = pps * shares

        if total > cash:
            return apology("Not enough funds")

        db.execute("UPDATE users SET cash = cash - :total WHERE id=:user_id", total=total, user_id=session["user_id"])
        db.execute("INSERT INTO data (user_id, symbol, shares, pricepershare) VALUES (:user_id, :symbol, :shares, :pricepershare);",
                                                                                    user_id=session["user_id"],
                                                                                    symbol=symbol,
                                                                                    shares=shares,
                                                                                    pricepershare=pps)
        flash("Bought!")
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT symbol, pricepershare, shares, datetime FROM data WHERE user_id = :user_id ORDER BY datetime ASC", user_id=session["user_id"])
    return render_template("history.html", transactions=transactions)

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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Missing symbol")

        stock = lookup(request.form.get("symbol"))

        if not stock:
            return apology("Invalid symbol")

        return render_template("quoted.html", name=stock["name"], price=usd(stock["price"]), symbol=stock["symbol"])

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("Enter a username")

        elif not request.form.get("password"):
            return apology("Enter a password")

        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("Passwords do not match")

        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        if len(rows) > 0:
            return apology("Passwords do not match")

        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=request.form.get("username"),
                                                                        hash=generate_password_hash(request.form.get("password")))

        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))
        session["user_id"] = rows[0]['id']

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Missing symbol")

        if not request.form.get("shares"):
            return apology("Missing shares")

        if int(request.form.get("shares")) <= 0:
            return apology("Shares must be positive integer")

        stock = lookup(request.form.get("symbol"))

        if not stock:
            return apology("Invalid symbol")

        total_stocks = db.execute("SELECT SUM(shares) as totalshares FROM data WHERE user_id = :user_id AND symbol = :symbol GROUP BY symbol",
                           user_id=session["user_id"], symbol=request.form.get("symbol"))

        if len(total_stocks) < 1 or total_stocks[0]["totalshares"] <= 0:
            return apology("You don't own this stock")

        if total_stocks[0]["totalshares"] < int(request.form.get("shares")):
            return apology("You don't own that many shares")

        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        cash = rows[0]["cash"]
        pps = stock["price"]

        total = pps * int(request.form.get("shares"))

        db.execute("UPDATE users SET cash = cash + :total WHERE id = :user_id", total=total, user_id=session["user_id"])
        db.execute("INSERT INTO data (user_id, symbol, shares, pricepershare) VALUES (:user_id, :symbol, :shares, :pricepershare);",
                                                                                    user_id=session["user_id"],
                                                                                    symbol=request.form.get("symbol"),
                                                                                    shares=-int(request.form.get("shares")),
                                                                                    pricepershare=pps)
        flash("Sold!")
        return redirect('/')
    else:
        stocks = db.execute("SELECT symbol, SUM(shares) as totalshares FROM data WHERE user_id = :user_id GROUP BY symbol HAVING totalshares > 0", user_id=session["user_id"])
        for stock in stocks:
            print(stock["symbol"])
        return render_template("sell.html", stocks=stocks)

@app.route("/addcash", methods=["GET", "POST"])
@login_required
def add_cash():
    """Add cash to account"""
    if request.method == "POST":
        try:
            amount = float(request.form.get("amount"))
        except:
            return apology("Enter valid amount")

        if amount <= 0:
            return apology("You can only add funds")

        db.execute("UPDATE users SET cash = cash + :amount WHERE id = :user_id", user_id=session["user_id"], amount=amount)
        flash("Added successfully!")
        return redirect('/')
    else:
        return render_template("addcash.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
