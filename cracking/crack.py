import csv, time, os, itertools, hashlib
import bcrypt
from argon2 import PasswordHasher

dirname = os.path.dirname(os.path.abspath(__file__))
USERS_CSV = os.path.join(dirname, 'task 7 - cracking', 'users.csv')
WORDLIST_PATH = os.path.join(dirname, 'task 7 - cracking', 'wordlist.txt')
ph = PasswordHasher()

def load_users(path):
    rows = []
    with open(path, newline='', encoding='utf-8') as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(row)
    return rows

def check_bcrypt(stored_hash, password_bytes):
    try:
        return bcrypt.checkpw(password_bytes, stored_hash.encode())
    except Exception:
        return False

def check_argon2(stored_hash, password_str):
    try:
        return ph.verify(stored_hash, password_str)
    except Exception:
        return False

def check_sha256_hex(stored_hex, salt_hex, password_bytes):
    try:
        salt = bytes.fromhex(salt_hex)
    except Exception:
        return False
    return hashlib.sha256(salt + password_bytes).hexdigest() == stored_hex

def check_sha3_hex(stored_hex, salt_hex, password_bytes):
    try:
        salt = bytes.fromhex(salt_hex)
    except Exception:
        return False
    return hashlib.sha3_256(salt + password_bytes).hexdigest() == stored_hex

def verify_record(record, pw_bytes):
    alg = (record.get("alg") or "").lower()
    stored = record.get("pwd_hash") or ""
    salt = record.get("salt") or ""
    if alg == ("argon2"):
        return check_argon2(stored, pw_bytes.decode(errors="ignore"))
    if alg == "bcrypt":
        return check_bcrypt(stored, pw_bytes)
    if alg == "sha256":
        return check_sha256_hex(stored, salt, pw_bytes)
    if alg == "sha3":
        return check_sha3_hex(stored, salt, pw_bytes)
    return False

def dictionary_attack(records, wordlist_path):
    print("Dictionary attack using:", wordlist_path)
    with open(wordlist_path, "rb") as f:
        words = [w.strip() for w in f if w.strip()]
    results = []
    for i, rec in enumerate(records):
        user = rec.get("username") or f"row{i}"
        print("Trying", user)
        start = time.time()
        found = None
        for w in words:
            if verify_record(rec, w):
                found = w.decode(errors="ignore")
                break
        elapsed = time.time() - start
        print("  ->", user, "found:", bool(found), "time:", f"{elapsed:.2f}s")
        results.append((user, found or "", elapsed))
    return results

def brute_force_attack(records, charset, maxlen):
    print("Brute-force attack: charset_len=", len(charset), "maxlen=", maxlen)
    results = []
    for i, rec in enumerate(records):
        user = rec.get("username") or f"row{i}"
        print("Bruteforcing", user)
        start = time.time()
        found = None
        for L in range(1, maxlen+1):
            for tup in itertools.product(charset, repeat=L):
                cand = "".join(tup).encode()
                if verify_record(rec, cand):
                    found = cand.decode()
                    break
            if found:
                break
        elapsed = time.time() - start
        print("  ->", user, "found:", bool(found), "time:", f"{elapsed:.2f}s")
        results.append((user, found or "", elapsed))
    return results

def save_results(results, out_path):
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["username", "found_password", "time_seconds"])
        for r in results:
            w.writerow([r[0], r[1], f"{r[2]:.4f}"])
    print("Wrote results to", out_path)

def main():
    print("Loading users from", USERS_CSV)
    records = load_users(USERS_CSV)
    
    dictionary_results = dictionary_attack(records, WORDLIST_PATH)
    save_results(dictionary_results, 'dictionary_results.csv')
    
    BRUTE_MAXLEN = 4
    BRUTE_CHARSET = "0123456789"
    brute_force_results = brute_force_attack(records, BRUTE_CHARSET, BRUTE_MAXLEN)
    save_results(brute_force_results, 'brute_force_results.csv')

if __name__ == "__main__":
    main()
