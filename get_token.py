import requests
import json

API_BASE = "http://localhost:5000/api"

def login(username, password):
    print(f"Logging in as {username}...")
    try:
        resp = requests.post(f"{API_BASE}/auth/login", json={"username": username, "password": password})
        if resp.status_code == 200:
            token = resp.json().get('token')
            print("Login successful.")
            return token
        else:
            print(f"Login failed: {resp.status_code} - {resp.text}")
            return None
    except Exception as e:
        print(f"Login error: {e}")
        return None

if __name__ == "__main__":
    token = login("admin", "admin123")
    
    if token:
        print(f"TOKEN: {token}")
        with open("token.txt", "w") as f:
            f.write(token)
    else:
        print("Could not obtain token.")
