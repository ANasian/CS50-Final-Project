import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
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
    stocks = db.execute("""SELECT symbol, name, SUM(shares) AS shares
                        FROM transactions WHERE user_id = :user_id GROUP BY symbol""", user_id=session['user_id'])
    portfolio = []
    total = 0
    for item in stocks:
        #get() take the value of the correspondant key in dict
        quotation = lookup(item.get('symbol'))
        price = quotation.get('price')
        value = price * item.get('shares')
        item['price'] = usd(price)
        item['value'] = usd(value)
        portfolio.append(item)
        total += value

    #get amount of cash for the user
    cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session['user_id'])
    cash = cash[0]['cash']

    #quering for labels (name) and data (shares) for the chart.js

    rowP = db.execute("SELECT symbol, price, SUM(shares) AS shares FROM transactions WHERE user_id = :user_id GROUP BY symbol", user_id=session['user_id'])
    symbol = []
    value =[]
    data = []

    for d in rowP:
        data.append(d.get('shares'))

    for s in rowP:
        if s.get("shares") != 0:
            sym = s.get("symbol")
            symbol.append(sym)

    for p in rowP:
        if p.get("shares") != 0:
            quot = lookup(p.get("symbol"))
            item = quot.get("price") * p.get("shares")
            value.append(item)


    return render_template("index.html", portfolio=portfolio, cash=usd(cash), total=usd(total), grand_total = usd(total + cash), data=data, symbol=symbol, value=value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        quotation = lookup(symbol)

        # checking if symbol is right
        if quotation == None or not symbol:
            return apology("Invalid symbol", 400)
        if not shares.isdigit():
            return apology("Please provide a positive numeric number", 400)

        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        amount = quotation['price'] * int(request.form.get('shares'))

        #Checking if the balance of the user is enough
        if amount > cash:
            return apology("Sorry you can't afford that!")

        #insert the transaction into the tx table
        db.execute("""INSERT INTO transactions (user_id, symbol, name, shares, price, type)
                    VALUES (?, ?, ?, ?, ?, ?)""", session['user_id'], quotation['symbol'], quotation['name'], int(request.form.get('shares')), quotation['price'], "BUY")

        #update the amount of cash of the users
        db.execute("UPDATE users SET cash = cash - :amount WHERE id = :user_id", amount=amount, user_id=session['user_id'])
        flash('Succesfully Bought!')

        return redirect('/')

    else:
        return render_template("buy.html")




@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    record = db.execute("SELECT symbol, shares, price, type, time FROM transactions WHERE user_id = :user_id AND time >= date('now', '-10 day')", user_id=session['user_id'])
    history_record = []

    for item in record:
        item['price'] = usd(item.get('price'))
        history_record.append(item)

    return render_template("history.html", history_record=history_record)


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

    if request.method == "POST":
        quotation = lookup(request.form.get("symbol"))

        if not request.form.get("symbol"):
            return apology("Must provide a symbol", 400)
        if quotation == None:
            return apology("Invalid symbol", 400)

        symbol = quotation.get("symbol")
        price = quotation.get("price")
        name = quotation.get("name")

        return render_template("quoted.html", symbol=symbol, price=usd(price), name=name)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        # Ensure username was submitted
        username = request.form.get("username")
        checkUsername = db.execute("SELECT username FROM users WHERE username =?", username)
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')
        hashPswd = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)

        if len(checkUsername) != 0:
            return apology("Username already exist", 400)

        if password != confirmation:
            return apology('password must be the same', 400)

        db.execute("INSERT INTO users (username, hash) VALUES (?,?)", username, hashPswd)
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    #get all the shares symbols in the portfolio of the current user
    symbols_own = db.execute("SELECT symbol FROM transactions WHERE user_id = :user_id GROUP BY symbol", user_id=session['user_id'])

    if request.method == "POST":
        symbol = request.form.get("symbol")
        quotation = lookup(symbol)
        amount = quotation['price'] * int(request.form.get('shares'))
        share_own = db.execute("SELECT SUM(shares) AS shares FROM transactions WHERE user_id = :user_id AND symbol = :symbol", user_id=session['user_id'], symbol=symbol)

        #control if you can sell the numbers of shares selected
        if share_own[0]['shares'] < int(request.form.get('shares')):
            return apology("Too much shares, you don't own them", 400)

        #insert the transaction into the tx table
        db.execute("""INSERT INTO transactions (user_id, symbol, name, shares, price, type)
                    VALUES (?, ?, ?, ?, ?, ?)""", session['user_id'], quotation['symbol'], quotation['name'], (int(request.form.get('shares')) * (-1)), quotation['price'], "SELL")

        #update the amount of cash of the users
        db.execute("UPDATE users SET cash = cash + :amount WHERE id = :user_id", amount=amount, user_id=session['user_id'])

        flash('Succesfully Sold!')

        return redirect('/')

    else:
        return render_template("sell.html", symbols_own=symbols_own)

@app.route("/change_pswd", methods=["GET", "POST"])
@login_required
def change():
    """Change User Pswd"""
    if request.method == "POST":
        oldPswd = db.execute("SELECT hash FROM users WHERE id = :user_id", user_id=session['user_id'])
        newPswd = request.form.get('newPswd')
        hashNewPswd = generate_password_hash(newPswd, method='pbkdf2:sha256', salt_length=8)

        #verify the current pswd is correct
        if not check_password_hash(oldPswd[0]["hash"], request.form.get("oldPswd")):
            return apology("Current pswd not correct")
        #verify the new pswds coincide
        if newPswd != request.form.get('confirmationPswd'):
            return apology("New pswd don't coincide")

        db.execute("UPDATE users SET hash = :newHash WHERE id = :user_id", newHash=hashNewPswd, user_id=session['user_id'])
        flash("Password has been changed, the new password apply to the next Log In")
        return redirect("/")

    else:
        return render_template("change.html")








def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
