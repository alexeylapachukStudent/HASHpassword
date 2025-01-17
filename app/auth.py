from datetime import datetime, timedelta
from bcrypt import checkpw, gensalt, hashpw
from cryptography.fernet import Fernet
import pyotp, re
from app.database import get_db_connection
import sqlite3

# Function checks the length of the password and if the username is alphanumeric
def validate_input(username, password):
    if not (6 <= len(password) <= 20):
        raise ValueError("Password must be between 6 and 20 characters")
    if not username.isalnum():
        raise ValueError("Username must be alphanumeric")


# Function check if the user provided a valid email address
def validate_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, email):
        raise ValueError("Invalid email address")
    
    

# Function checks if the account should be locked or not
def is_account_locked(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT failed_logins, last_login FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
    
        if result:
            failed_logins, last_login = result
            if failed_logins >= 5 and datetime.now() - last_login < timedelta(minutes=5):
                return True
    finally:
        conn.close()
    return False

# Function logs events in the database
def logs_events(event_type, username, status, description=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO logs (event_type, user_id, status, description) VALUES (?, ?, ?, ?)", (event_type, username, status, description))
    
        conn.commit()
    finally:
        conn.close()
    


# Function that provides the main functionality of the registration
def register(username, password, email):
    try:
        
        # Validation of the input
        validate_input(username, password)
        validate_email(email)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Checking if the user is already registered
            cursor.execute("SELECT 1 FROM users WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                raise ValueError("User is already registered")
            # Generating a hashed password
            hashed_password= hashpw(password.encode(), gensalt())
            
            # Updating the database with the new user
            cursor.execute("INSERT INTO users (username, password, email, last_login) VALUES (?, ?, ?, ?)", (username, hashed_password, email, datetime.now()))
            
            conn.commit()
            
            logs_events("register", username, "success", "User registered successfully")
            
            return True
        finally:
            conn.close()
    except ValueError as e:
        logs_events("register", username, "failed", str(e))
        print("Registration error")
        return False        
    
    except Exception as e:
        logs_events("register", username, "failed", str(e))
        return False   
        

# Function that provides the main functionality of the login
def login(username, password):
    
    # Function checks if the account is locked
    if is_account_locked(username):
        logs_events("login", username, "failed", "Account is locked")
        print("Account is locked")
        return False
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password, failed_logins FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
   
        # Checks if the password is correct
        if result and checkpw(password.encode(), result[0]):
            cursor.execute("UPDATE users SET failed_logins = 0, last_login = ?", (datetime.now(),))
            
            conn.commit()
            
            # Logs the event when the user logs in
            logs_events("login", username, "success", "User logged in successfully")
            
            return True
        # Checks if the password is incorrect
        else:
            cursor.execute("UPDATE users SET failed_logins = failed_logins + 1, last_login = ?", (datetime.now(),))
            
            conn.commit()
            
            # Logs the event when the user fails to log in
            logs_events("login", username, "failed", "User failed to log in")
            return False
    finally:
        conn.close()
        
# Function provides the main functionality of the password change
def change_password(username, old_password, new_password):
    # Checks if the old password is correct
    if not login(username, old_password):
        return "Invalid password"
    
    try:
        # Checks if the new password is valid
        validate_input(username, new_password)
        
        if checkpw(new_password.encode(), old_password.encode()):
            return "New password must be different from the old password"
        
        # Generating a hashed password
        hashed_password = hashpw(new_password.encode(), gensalt())
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Updating the password in the database that is connected to the user
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
            
            conn.commit()
            # Logging the event when the user changes the password
            logs_events("change_password", username, "success", "User changed password successfully")
            
            return "Password was changed successfully!"
        finally:
            conn.close()
    except Exception as e:
        # Exception when the password change fails
        logs_events("change_password", username, "failed", str(e))
        return "Password change failed"
    
    
# Function that provides the main functionality of the role definition
def define_role(username):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
    
        cursor.execute("SELECT role FROM users WHERE username = ?", (username,))

        result = cursor.fetchone()
        return result[0] if result else None
    except Exception as e:
        logs_events("define_role", username, "failed", str(e))
        return None
    finally:
        conn.close()
        
        
# Checks if the user is an admin
def is_admin(username):
    return define_role(username) == "admin"

# Function generates a secret for the 2FA
def generate_otp_secret():
    return pyotp.random_base32()

# Function verifies the OTP
def verify_otp(secret, opt_code):
    totp = pyotp.TOTP(secret)
    print(opt_code)
    print(totp.verify(opt_code))
    return totp.verify(opt_code)

# Define the cipher using a key
key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt_secret(secret):
    return cipher.encrypt(secret.encode()).decode()

def decrypt_secret(secret):
    return cipher.decrypt(secret.encode()).decode()

# Enable the 2FA
def enable_2fa(username):
    try:
        # Generating OTP secret
        secret = generate_otp_secret()
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT opt_secret FROM users WHERE username = ?", (username,))
            
            # Checks if the 2FA is already enabled
            print(cursor.fetchone())
            if cursor.fetchone() is not None:
                raise ValueError("2FA is already enabled")
            
            print("2FA is not enabled")
            
            # Encrypt and store OTP secret
            
            cursor.execute("UPDATE users SET opt_secret = ? WHERE username = ?", (secret, username))
            conn.commit()
            

            logs_events("2fa", username, "success", "2FA enabled")
            return secret
        finally:
            conn.close()
    except Exception as e:
        logs_events("2fa", username, "failed", str(e))
        return None


# Verify 2FA for a user by comparing the provided OTP
def verify_2fa(username, otp_code):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT opt_secret FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        
        if result:
            # Decrypt stored OTP secret
            
            secret = result[0]
            
            if verify_otp(secret, otp_code):
                logs_events("2fa", username, "success", "2FA verified")
                return True
            else:
                logs_events("2fa", username, "failed", "2FA verification failed")
                return False
        else:
            logs_events("2fa", username, "failed", "2FA not enabled")
            return False
        
    except Exception as e:
        logs_events("2fa", username, "failed", str(e))
        return False
    finally:
        conn.close()