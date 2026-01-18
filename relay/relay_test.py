import requests
import pyotp
import time
import pandas as pd

RELAY = "http://127.0.0.1:8000"
REAL  = "http://127.0.0.1:5000"
USER_TOTP = "totp_test_user"
USER_HOTP = "hotp_test_user"
PASSWORD = "Pass123!"

TOTP_TRIALS = 8
HOTP_TRIALS = 8
INTER_TRIAL_DELAY = 1.0

def create_users():
    requests.post(REAL + "/register", json={"username": USER_TOTP, "password": PASSWORD})
    r1 = requests.post(REAL + "/mfa/setup", json={"username": USER_TOTP})
    print(f"TOTP status: {r1.status_code}")
    totp_secret = r1.json().get("secret")

    requests.post(REAL + "/register", json={"username": USER_HOTP, "password": PASSWORD})
    r2 = requests.post(REAL + "/mfa/setup/hotp", json={"username": USER_HOTP})
    print(f"HOTP status: {r2.status_code}")
    hotp_secret = r2.json().get("secret")

    return totp_secret, hotp_secret

def run_totp_trials(totp_secret, trials=TOTP_TRIALS, delay=INTER_TRIAL_DELAY):
    totp = pyotp.TOTP(totp_secret)
    rows = []
    for i in range(trials):
        code = totp.now()
        payload = {"username": USER_TOTP, "code": code}
        t0 = time.time()
        resp = requests.post(RELAY + "/mfa/verify", json=payload)
        latency_ms = (time.time() - t0) * 1000.0
        success = (resp.status_code == 200)
        rows.append({
            "mfa_type": "TOTP",
            "trial": i,
            "code": code,
            "status": resp.status_code,
            "latency_ms": latency_ms,
            "success": int(bool(success))
        })
        print(f"TOTP trial {i}: code={code}, status={resp.status_code}, latency_ms={latency_ms:.1f}")
        time.sleep(delay)
    return rows

def run_hotp_trials(hotp_secret, trials=HOTP_TRIALS, delay=INTER_TRIAL_DELAY):
    hotp = pyotp.HOTP(hotp_secret)
    rows = []
    for i in range(trials):
        code = hotp.at(i)
        payload = {"username": USER_HOTP, "code": code}
        t0 = time.time()
        resp = requests.post(RELAY + "/mfa/verify", json=payload)
        latency_ms = (time.time() - t0) * 1000.0
        success = (resp.status_code == 200)
        rows.append({
            "mfa_type": "HOTP",
            "trial": i,
            "code": code,
            "status": resp.status_code,
            "latency_ms": latency_ms,
            "success": int(bool(success))
        })
        print(f"HOTP trial {i}: code={code}, status={resp.status_code}, latency_ms={latency_ms:.1f}")
        time.sleep(delay)
    return rows

if __name__ == "__main__":
    print("Creating users and setting up MFA...")
    totp_secret, hotp_secret = create_users()

    print("\nRunning TOTP trials through relay...")
    totp_rows = run_totp_trials(totp_secret)

    print("\nRunning HOTP trials through relay...")
    hotp_rows = run_hotp_trials(hotp_secret)

    df = pd.DataFrame(totp_rows + hotp_rows)

    df = df[["mfa_type", "trial", "code", "status", "success", "latency_ms"]]

    pd.set_option("display.float_format", "{:.1f}".format)
    print(df)
