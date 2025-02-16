# Secure User Authentication with Bcrypt and HMAC-Peppered Hashing

Project summary: https://www.linkedin.com/in/mj-yuan-786678324/details/projects/
This project demonstrates a secure way to store and verify user passwords in a SQLite database using Python. It leverages the following security mechanisms:

- **bcrypt**: A password hashing function designed for secure password storage.
- **HMAC with BLAKE2b**: Applies an additional layer of security using a secret pepper before hashing.
- **SQLite**: A lightweight relational database for storing user credentials.
- **dotenv**: Loads environment variables from a `.env` file for configuration.

## Features

- **Secure Password Hashing**: Combines HMAC (with a secret pepper) and bcrypt to securely hash passwords.
- **User Registration**: Stores unique usernames and securely hashed passwords in an SQLite database.
- **Password Verification**: Compares user-entered passwords with the stored secure hash.
- **Environment Configuration**: Optionally load a secret pepper from a `.env` file.

## Prerequisites

- Python 3.7 or higher
- The following Python packages:
  - `bcrypt`
  - `hmac` (built-in)
  - `sqlite3` (built-in)
  - `hashlib` (built-in)
  - `python-dotenv`

Install the required packages using pip:

```bash
pip install bcrypt python-dotenv
```

## Setup
1. Clone the Repository
```bash
git clone https://github.com/yourusername/secure-user-auth.git
cd secure-user-auth
```

2. Create a .env File (Optional)
- To use a custom secret pepper, create a .env file in the root of the project:
```bash
SECRET_PEPPER=your_custom_secret_pepper_value
```
- If no .env file is provided, the default pepper value will be used.

3. Initialize the Database
- The database is automatically created when you run the script. It creates a file called users.db with a users table if it does not exist.

## How It Works
- Database Initialization
  - The create_database() function sets up the SQLite database with a users table, including columns for an auto-incremented id, a unique username, and a password_hash.

- Password Hashing
  - The secure_hash(password: str) function uses HMAC with BLAKE2b to mix the password with a secret pepper. The resulting digest is then hashed using bcrypt with 14 rounds of salt generation. This hashed password is what gets stored in the database.

- User Registration
  - The store_user(username: str, password: str) function creates a new user record in the database using the secure hash of the password. It handles duplicate usernames gracefully.

- Password Verification
  - The verify_password(username: str, entered_password: str) function retrieves the stored hash for a given username and compares it with the hash of the entered password (after applying the same HMAC-peppering process).

## Usage
- Run the script directly to initialize the database, add sample users, and test password verification:
```bash
python your_script_name.py
```

- Example output:
```bash
User 'alice' added successfully!
User 'bob' added successfully!

Testing Password Verification:
Alice correct password: True
Alice wrong password: False
User 'charlie' not found.
Non-existent user: False
```

## Security Considerations
- Secret Pepper: The pepper value is used as an additional layer of security and should be kept secret. Use a secure, randomly generated value and store it in an environment variable rather than hardcoding it.
- Password Storage: Never store plain text passwords. Always use secure hashing (as demonstrated) to protect user credentials.
- Bcrypt Rounds: The bcrypt hashing rounds (set to 14 in this example) can be adjusted based on your security requirements and performance considerations.

## License
- This project is licensed under the MIT License. See the LICENSE file for more details.

## Acknowledgments
- bcrypt - Used for securely hashing passwords with salting.
- hmac - Used for implementing a cryptographic keyed-hash message authentication code (HMAC) to add extra security.
- blake2b - A secure cryptographic hash function used in conjunction with HMAC.
- sqlite3 - Embedded database engine for storing user credentials.
- python-dotenv - Helps manage sensitive information securely using environment variables.
- os - Used for handling environment variables and file system interactions.
- Special thanks to the open-source community for providing best practices in cryptographic security and password storage.
