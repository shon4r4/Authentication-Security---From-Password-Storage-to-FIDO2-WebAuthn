import requests, pyotp

BASE_URL = "http://127.0.0.1:5000"

USERNAME = "marge"
PASSWORD = "password"
HEADERS = {"Content-Type": "application/json"}

# Register user
print("Registering user...")
r = requests.post(f"{BASE_URL}/register", json={"username": USERNAME, "password": PASSWORD})
print("Status:", r.status_code, r.json())

# Set up HOTP MFA
print("\nSetting up HOTP MFA...")
r = requests.post(f"{BASE_URL}/mfa/setup/hotp", json={"username": USERNAME})
data = r.json()
print("Status:", r.status_code)
print("Response:", data)

secret = data["secret"]
hotp = pyotp.HOTP(secret)
counter = 0

print(f"\nSecret: {secret}")
print(f"Initial counter = {counter}")

# Generate valid code and verify
code = hotp.at(counter)
print(f"\nFirst code ({code})\nCounter={counter}")
r = requests.post(f"{BASE_URL}/mfa/verify", json={"username": USERNAME, "code": code})
print("Status:", r.status_code, r.json())
counter += 1

# Simulate client generating and not verifying codes
print("\n\nClient generating and not verifying codes...")
skipped = 3
for i in range(skipped):
    future_code = hotp.at(counter + i)
    print(f"Code {future_code}\nCounter={counter + i}")
counter += skipped

# Try verify (server should reject)
future_code = hotp.at(counter)
print(f"\nDesynced code {future_code}\nCounter={counter}")
r = requests.post(f"{BASE_URL}/mfa/verify", json={"username": USERNAME, "code": future_code})
print("Status:", r.status_code, r.json())

# Try resync
print("\nTrying to resync...")
for i in range(1, 6):
    code = hotp.at(counter + i)
    print(f"Trying code {code} (counter={counter + i}) ...")
    r = requests.post(f"{BASE_URL}/mfa/verify", json={"username": USERNAME, "code": code})
    print("→", r.status_code, r.json())
