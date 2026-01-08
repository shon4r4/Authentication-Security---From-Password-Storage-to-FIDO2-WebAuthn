# Advanced Authentication & Security Research Suite


**Authors:** Nenand S

---

## Executive summary

A full-stack demonstration of secure credential management, FIDO2/WebAuthn, and cryptographic vulnerability research.
Beyond implementation, this project includes a Security Research Suite with tools to simulate and mitigate timing attacks, MITM relays, and brute-force cracking.

[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Security](https://img.shields.io/badge/Security-FIDO2%20%2F%20WebAuthn-green.svg)](https://fidoalliance.org/)

---

## Key Features

1. ### Multi-Scheme Password Hashing

Benchmark various schemes to demonstrate resistance against GPU-accelerated hardware:

    Modern Standards: Argon2id (memory-hard) and bcrypt (key-stretching).

Defensive Layers: Implementation of per-user unique salts and a global system-wide "pepper".

Integrity Protection: All API responses are signed with HMAC-SHA256 using constant-time verification to prevent tampering and timing leaks.

2. ### Multi-Factor Authentication (MFA)

    TOTP & HOTP: Enrollment via QR codes with configurable drift windows (±1) to balance security and usability.

Security Analysis: Research on counter desynchronization and atomic consumption of codes.

3. ### FIDO2 / WebAuthn (Phishing Resistance)

    Full implementation using python-fido2.

Credentials are cryptographically bound to the domain (RP-ID) and browser origin, making them immune to the relay attacks that compromise TOTP.


---

## Security Research & Empirical Results

### Password Cracking (/cracking)

Using dictionary and brute-force attacks, we benchmarked the security of different algorithms:
Algorithm,  Avg. Time (s),  Vulnerability Status
SHA-256,    ~0.0011s,High:  Instant discovery with fast hashes.
Argon2,     ~18.32s,Low:    Memory-hardness effectively throttles attempts.
bcrypt,     ~74.72s,Low:    Key-stretching provides superior resistance.


### Timing Attack Analysis (/timing_attack)

Using micro-benchmarking, we proved that naive comparisons leak secrets via execution time:

    Insecure Recovery: Naive comparisons allowed the partial recovery of secrets.

Defensive Result: Implementation of hmac.compare_digest() successfully neutralized the side-channel attack.

### MITM Relay & Desync (/relay)

Using a local proxy, we demonstrated critical behaviors during a relay attack:

    TOTP Result: 100% replay success rate when replayed within the server's accepted window.

WebAuthn Result: 0% success rate; assertions were rejected due to origin binding.


---

## Project Structure

* '/app'                  # Source code for the Flask API
* '/artifacts'            # Database exports and QR enrollment samples
* '/cracking'             # Dictionary & Brute-force simulation scripts
* '/timing_attack'        # Timing leakage benchmarking tools
* '/relay*                # MITM local proxy and relay experiments
* '/testing'              # Request-based functional test scripts


---

## Installation & Setup

    Clone the Repo: git clone https://github.com/shon4r4/Authentication-Security---From-Password-Storage-to-FIDO2-WebAuthn.git

    Dependencies: pip install flask flask-sqlalchemy fido2 argon2-cffi bcrypt pyotp qrcode

    Run: python app.py

    Access: Open http://localhost:5000 to view the research frontend.