from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_pymongo import PyMongo
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
CORS(app)
app.config['MONGO_URI'] = 'mongodb://localhost:27017/mydatabase'
mongo = PyMongo(app)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Missing email or password'}), 400

    # Check if the email already exists
    if mongo.db.users.find_one({'email': email}):
        return jsonify({'error': 'Email already exists'}), 409

    # Hash the password before storing it in the database
    hashed_password = generate_password_hash(password)

    # Insert user into the database
    user_id = mongo.db.users.insert_one({'email': email, 'password': hashed_password}).inserted_id

    return jsonify({'message': 'User signed up successfully', 'user_id': str(user_id)}), 201

@app.route('/signin', methods=['POST'])
def signin():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Missing email or password'}), 400

    # Find user by email
    user = mongo.db.users.find_one({'email': email})

    if not user or not check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid email or password'}), 401

    return jsonify({'message': 'User signed in successfully', 'user_id': str(user['_id'])}), 200

if __name__ == '__main__':
    app.run(debug=True)
