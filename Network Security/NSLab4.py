from flask import Flask, request, jsonify
import jwt
import datetime

app = Flask(__name__)

SECRET_KEY = "mysecretkey"

users = {
    "admin": "1234"
}

@app.route("/")
def home():
    return "Server is running!"

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data["username"]
    password = data["password"]

    if username in users and users[username] == password:

        token = jwt.encode(
            {
                "user": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=300)
            },
            SECRET_KEY,
            algorithm="HS256"
        )

        token = token.decode("utf-8")

        return jsonify({"token": token})

    return jsonify({"message": "Invalid credentials"}), 401


@app.route("/protected")
def protected():

    token = request.headers.get("Authorization")

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"message": "Access granted"})
    except:
        return jsonify({"message": "Invalid token"}), 403


if __name__ == "__main__":
    app.run(debug=True, port=5001)
    
    
    
    
    
    
# NONE ATTACK

# from flask import Flask, request, jsonify
# import jwt
# import datetime

# app = Flask(__name__)

# SECRET_KEY = "mysecretkey"

# users = {
#     "admin": "1234"
# }

# @app.route("/login", methods=["POST"])
# def login():
#     data = request.json
#     username = data["username"]
#     password = data["password"]

#     if username in users and users[username] == password:

#         token = jwt.encode(
#             {
#                 "user": username,
#                 "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
#             },
#             SECRET_KEY,
#             algorithm="HS256"
#         )

#         token = token.decode("utf-8")

#         return jsonify({"token": token})

#     return jsonify({"message": "Invalid credentials"}), 401


# @app.route("/protected")
# def protected():

#     token = request.headers.get("Authorization")

    # try:
    #     decoded = jwt.decode(token, SECRET_KEY, verify=False)
    #     return jsonify({"message": "Access granted"})
    
#     except:
#         return jsonify({"message": "Invalid token"}), 403


# if __name__ == "__main__":
#     app.run(debug=True)





# EXPIRY ATTACK

# from flask import Flask, request, jsonify
# import jwt
# import datetime

# app = Flask(__name__)

# SECRET_KEY = "mysecretkey"

# users = {
#     "admin": "1234"
# }

# @app.route("/login", methods=["POST"])
# def login():
#     data = request.json
#     username = data["username"]
#     password = data["password"]

#     if username in users and users[username] == password:

#         token = jwt.encode(
#             {
#                 "user": username,
#                 "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
#             },
#             SECRET_KEY,
#             algorithm="HS256"
#         )

#         token = token.decode("utf-8")

#         return jsonify({"token": token})

#     return jsonify({"message": "Invalid credentials"}), 401


# @app.route("/protected")
# def protected():

#     token = request.headers.get("Authorization")

#     try:
#         decoded = jwt.decode(token, SECRET_KEY, options={"verify_exp": False})
#         return jsonify({"message": "Access granted"})
#     except:
#         return jsonify({"message": "Invalid token"}), 403


# if __name__ == "__main__":
#     app.run(debug=True)