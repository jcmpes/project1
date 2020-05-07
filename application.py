import os
import re

from flask import Flask, flash, session, request, render_template, redirect
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import password_check, login_required

app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
    raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
db = scoped_session(sessionmaker(bind=engine))


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    """ Allows user to search for books and see results"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        query = request.form.get("query")

        if not query:
            flash("Nothing to search for", "warning")
            return redirect("/")

        results = db.execute("SELECT * FROM books WHERE isbn LIKE :query OR author LIKE :query OR title LIKE :query ", {"query": "%" + query + "%"}).fetchall()
        if not results:
            flash("Book not found, sorry", "warning")

        return render_template("index.html", results=results)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("index.html")

@app.route("/book/<int:book_id>", methods=["GET", "POST"])
def book(book_id):
    """ Lists details about a single book """

    # Make sure book exists.
    book = db.execute("SELECT * FROM books WHERE id = :id", {"id": book_id}).fetchone()
    if book is None:
        flash("Invalid book ID", "warning")
        return redirect("/")

    # Load all reviews
    reviews = db.execute("SELECT * FROM reviews JOIN users ON reviews.user_id = users.id WHERE book_id = :book_id", {"book_id": book.id}).fetchall()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Manage new review.
        review = request.form.get("review")
        if review:

            # Show message if user has already reviewed this book.
            for review in reviews:
                if review.user_id == session["user_id"]:
                    flash("You have already reviewed this book. Thnak you.", "warning")
                    return render_template("book.html", book=book, reviews=reviews)

            # Update database with new review.
            db.execute("INSERT INTO reviews (book_id, user_id, review) VALUES (:book_id, :user_id, :review)", {"book_id": book.id, "user_id": session["user_id"], "review": review})
            db.commit()
            flash("Your review has been submitted", "success")

        # Get all book details:
        return render_template("book.html", book=book, reviews=reviews)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        # Get all book details:
        return render_template("book.html", book=book, reviews=reviews)

@app.route("/register", methods=["GET", "POST"])
def register():
    """ Register user """

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        hash = generate_password_hash(password)

        if not username:
            flash("No username", "warning")
            return render_template("register.html")

        if db.execute("SELECT * FROM users WHERE username = :username", {"username": username }).rowcount != 0:
            flash("User already exists", "warning")
            return render_template("register.html")

        if password != confirmation:
            flash("Passwords do not match", "warning")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password is too short", "warning")
            return render_template("register.html")

        else:
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                        {"username": username, "hash": hash})
            db.commit()
            flash(f"You have just registered the user '{username}'", "success")
            return redirect("/login")


    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """ User logs in """

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Ensure username was submitted
        if not username:
            flash("Please provide a username", "danger")
            return redirect("/login")

        # Ensure password was submitted
        if not password:
            flash("Password was left blank", "danger")
            return redirect("/login")

        # Query database for username
        row = db.execute("SELECT * FROM users WHERE username = :username",
                          {"username": username}).fetchone()

        # Ensure username exists and password is correct
        if row is None:
            flash("Invalid username and/or password", "danger")
            return redirect("/login")

        if not check_password_hash(row["hash"], password):
            flash("Invalid username and/or password", "danger")
            return redirect("/login")

        # Remember which user has logged in
        session["user_id"] = row["id"]

        # Redirect user to home page
        flash(f"You are logged in as '{username}'", "success")
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
