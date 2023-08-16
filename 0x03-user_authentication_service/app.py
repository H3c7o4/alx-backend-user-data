#!/usr/bin/env python3
"""
Basic Flask app
"""
from flask import abort, Flask, jsonify, request, redirect, url_for
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/', methods=['GET'])
def welcome():
    """ welcome """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users():
    """This function register a user
    """
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        user = AUTH.register_user(email, password)
        return jsonify({
            "email": email,
            "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    """This function logg a user
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        response.set_cookie('session_id', session_id)

        return response

    abort(401)


@app.route('/sessions', methods=['DELETE'])
def logout():
    """ Log a user out of the session
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session__id)

    if user:
        AUTH.destroy_session(user.id)
        return redirect(url_for('welcome'))

    abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
