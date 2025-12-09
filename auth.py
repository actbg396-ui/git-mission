import bcrypt
import os

USER_DATA_FILE = "users.txt"

def hash_password(plain_text_password):
    password_bytes = plain_text_password.encode("utf-8")
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password_bytes, salt)
    hashed_string = password_hash.decode("utf-8")
    return hashed_string

def verify_password(plain_text_password, hashed_string):
    password_bytes = plain_text_password.encode("utf-8")
    hash_bytes = hashed_string.encode("utf-8")
    is_valid = bcrypt.checkpw(password_bytes, hash_bytes)
    return is_valid

def register_user(username, password):
    if user_exists(username):
        print(f"Error: Username {username}already exists.")
        return False

    hashed_password = hash_password(password)

    with open(USER_DATA_FILE,'a') as file:
        file.write(f"{username},{hashed_password}\n")

    print(f"Success: User {username} registered.")

    return True


def user_exists(username):
    if not os.path.exists(USER_DATA_FILE):
        return False

    with open(USER_DATA_FILE,'r') as file:
        for line in file:
            parts = line.strip().split(",")
            if parts[0] == username:
                return True

    return False


def login_user(username, password):
    if not os.path.exists(USER_DATA_FILE):
        print(f"Error: No users registred. Register first please.")
        return False

    with open(USER_DATA_FILE,'r') as file:
        for line in file:
            parts = line.strip().split(",")
            if parts[0] == username:
                stored_hash = parts[1]

                if verify_password(password, stored_hash):
                    print(f"Success: User {username} logged in.")
                    return True
                else:
                    print(f"Error: Incorrect password. Try again.")
                    return False

    print("User not found.")
    return False

def validate_username(username):

    if username == "":
        return False, "Error: Username can not be empty."
    elif len(username) < 3:
        return False, "Username must be at least 3 characters long."
    elif len(username) > 20:
        return False, "Username must be at most 20 characters long."
    elif not username.replace(" ", "").isalnum():
        return False, "Username can only contain letters, numbers and dashes."
    else:
        return True, "Success: Username valid."


def validate_password(password):

    if not password:
        return False, "Password cannot be empty."

    if len(password) < 6:
        return False, "Password too short (minimum 6 characters)."

    if len(password) > 50:
        return False, "Password too long (maximum 50 characters)."

    if not any(c.isupper() for c in password):
        return False, "Password needs at least one uppercase letter."


    if not any(c.islower() for c in password):
        return False, "Password needs at least one lowercase letter."

    if not any(c.isdigit() for c in password):
        return False, "Password needs at least one number."

    return True, "Password is valid."

def display_menu():
 """Displays the main menu options."""
 print("\n" + "="*50)
 print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
 print(" Secure Authentication System")
 print("="*50)
 print("\n[1] Register a new user")
 print("[2] Login")
 print("[3] Exit")
 print("-"*50)

def main():
    """Displays the main menu options."""
    print("\n" + "=" * 50)
    print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print(" Secure Authentication System")
    print("=" * 50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-" * 50)

def main():
    """Main program loop."""
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password = input("Enter a password: ").strip()
            # Validate password
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            # Confirm password
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            # Register the user
            register_user(username, password)

        elif choice == '2':
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            # Attempt login
            if login_user(username, password):
                print("\nYou are now logged in.")
            print("In a real application, you would now access the dashboard")

            # Optional: Ask if they want to logout or exit
            input("\nPress Enter to return to main menu...")

        elif choice == '3':
            # Exit
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()





