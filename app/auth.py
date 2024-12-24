from datetime import datetime, timedelta
from bcrypt import checkpw, gensalt, hashpw
import pyotp
from database import get_db_connection


def validate_input(username, password):
    if not (6 <= len(password) <= 20):
        raise ValueError("Password must be between 6 and 20 characters")
    if not username.isalnum():
        raise ValueError("Username must be alphanumeric")
    

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


def logs_events(event_type, username, status, description=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO logs (event_type, username, status, description) VALUES (?, ?, ?, ?)", (event_type, username, status, description))
    
        conn.commit()
    finally:
        conn.close()
    



def register(username, password, email):
    try:
        validate_input(username, password)
        
        hashed_password = hashpw(password.encode(), gensalt())
        conn = get_db_connection()
        cursor = conn.cursor()
        # dopisat\
        try:
            cursor.execute("INSERT INTO users (username, password, email, role, failed_logins, last_login) VALUES (?, ?, ?, 'user', 0, NULL)", (username, hashed_password, email))
        
            conn.commit()
        finally:
            conn.close()
        
        return True
    except ValueError as e:
        logs_events("registration", username, "failed", str(e))
        print("Registration error")
        return False
    
        


def login(username, password):
    
    if is_account_locked(username):
        logs_events("login", username, "failed", "Account is locked")
        print("Account is locked")
        return False
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT password, failed_logins FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
   
    
        if result and checkpw(password.encode(), result[0]):
            cursor.execute("UPDATE users SET failed_logins = 0, last_login = ?", (datetime.now(),))
            
            conn.commit()
            
            logs_events("login", username, "success", "User logged in successfully")
            
            return True
        else:
            cursor.execute("UPDATE users SET failed_logins = failed_logins + 1, last_login = ?", (datetime.now(),))
            
            conn.commit()
            
            logs_events("login", username, "failed", "User failed to log in")
            return False
    finally:
        conn.close()
        

def change_password(username, old_password, new_password):
    if not login(username, old_password):
        return "Invalid password"
    
    try:
        validate_input(username, new_password)
        hashed_password = hashpw(new_password.encode(), gensalt())
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
            
            conn.commit()
            
            logs_events("change_password", username, "success", "User changed password successfully")
            
            return "Password was changed successfully!"
        finally:
            conn.close()
    except Exception as e:
        logs_events("change_password", username, "failed", str(e))
        return "Password change failed"
    
    

def define_role(username):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
    
        cursor.execute("SELECT role FROM users WHERE username = ?", (username,))

        result = cursor.fetchone()
        return result[0] if result else None
    finally:
        conn.close()
        

def is_admin(username):
    return define_role(username) == "admin"


def generate_otp_secret():
    return pyotp.random_base32()


def verify_otp(secret, opt_code):
    totp = pyotp.TOTP(secret)
    return totp.verify(opt_code)


def enable_2fa(username):
    try:
        secret = generate_otp_secret()
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE users SET opt_secret = ? WHERE username = ?", (secret, username))
            
            conn.commit()
            
            logs_events("2fa", username, "success", "2FA enabled")
            return secret
        finally:
            conn.close()
    except Exception as e:
        logs_events("2fa", username, "failed", str(e))
        return None
        
    
    
    
def verify_2fa(username, opt_code):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT opt_secret FROM users WHERE username = ?", (username,))
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        secret = result[0]
        return verify_otp(secret, opt_code)
    return False
    
    

    
        
