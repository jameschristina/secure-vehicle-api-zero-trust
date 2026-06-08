from flask import Blueprint, request, session, redirect, render_template

auth_bp = Blueprint("auth", __name__)

USERS = {
    "admin": "admin123",
    "analyst": "soc2024"
}


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        if USERS.get(u) == p:
            session["user"] = u
            return redirect("/dashboard")

        return "Invalid login", 401

    return render_template("login.html")


@auth_bp.route("/logout")
def logout():
    session.clear()
    return redirect("/login")
