# Simple-Redis-IAM

## 📋 Description

The following project constitutes an **IAM (Identity and Access Management)** system built on a Redis database with a Python-powered FastAPI backend service.

Both technologies deliver basic authentication and authorization methods to manage user access control for web applications.

While these services can be used in different scenarios for various web apps, ["The Movie Draft Pick"](https://github.com/DAVEisZERO/movie-draft-pick) frontend is an open-source SPA written in Angular that works perfectly in combination with this repository.

### 🎯 Goal

The principal goal of this project is to demonstrate good and bad code implementation regarding the [OWASP Top 10 2021](https://owasp.org/Top10/A00_2021_Introduction/). While the code is configured securely by default, additional "insecure" functions and configurations are provided to experiment with and showcase different OWASP vulnerabilities.

---

## 🚀 Getting Started

### 📦 Prerequisites

1. Update the `.env` file with your desired configuration changes. (default settings work without problems)
    - Provide the local/remote URL of your deployed frontend
2. Ensure you have `Docker/Podman` and `Python 3.13` installed
3. Set up SSL certificates fo local deployment

Local CA creation

    install mkcert (https://github.com/FiloSottile/mkcert)
    
    # Created a new local CA 💥
    1. mkcert -install
    
    #Created a new certificate valid for the following names 📜
    # 	- "example.com"
    # 	- "*.example.com"
    # 	- "example.test"
    # 	- "localhost"
    # 	- "127.0.0.1"
    # 	- "::1"
    #    The certificate is at "./example.com+5.pem" and the key at "./example.com+5-key.pem"
    
    2. mkcert example.com "*.example.com" example.test localhost 127.0.0.1 ::1
    
    3. save at 'simple-redis-aim/ssl_certs' both certificates (public cert and private key)
    
    4. based on the names, configure the .env file
        - more details on uvicorn set-up https://uvicorn.dev/deployment/#running-with-https

    
> Alternative, use Lets Encrypt for global solution. Set up is more complex.
    - https://letsencrypt.org/getting-started/

### 🔧 Build and Deploy

There are two deployment approaches, highlighting the importance of respecting **A06** and **A08** OWASP vulnerabilities:

- **A06:2021** – Vulnerable and Outdated Components
- **A08:2021** – Software and Data Integrity Failures

---

## 🔒 Secure Deployment

Keep the order of components initialization in mind.

### 1️⃣ Redis Setup

#### Step 1: Image Inspection & Integrity Check

```bash
podman run --rm quay.io/skopeo/stable inspect docker://docker.io/library/redis:latest
```

#### Step 2: Pull Using the Digest

```bash
podman pull docker.io/library/redis@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
```

#### Step 3: Verify Local Integrity

```bash
podman inspect --format='{{.Digest}}' redis
```

#### Step 4: Vulnerability Check

```bash
podman run --rm -v trivy_cache:/root/.cache/ aquasec/trivy image redis:latest
```

#### Step 5: Deploy Redis Container with Security Config

```bash
podman run -v ./infrastructure/config:/usr/local/etc/redis -p 6300:6300 --name secure_redis_iam redis redis-server /usr/local/etc/redis/redis.conf
```

### 2️⃣ FastAPI Server Setup

#### Step 1: Clone the Repository

```bash
git clone <repository-url>
cd simple-redis-iam
```

#### Step 2: Check for Outdated Components

```bash
pip list --outdated
pip install pip-check
pip-check
```

#### Step 3: Install Security Auditors

```bash
pip install pip-audit uv pip-tools
```

#### Step 4: Security Gate (Strict Mode)

```bash
pip-audit -r requirements.txt --strict --desc
```

> ⚠️ **Note:** This command fails (exit 1) if vulnerabilities are found.

#### Step 5: Update Dependencies & Start Service

```bash
pip-sync
python main.py
```

---

## ⚡ Non-Secure Deployment

> ⚠️ **Warning:** This deployment method is **NOT recommended** for production environments.

### Redis Setup

```bash
podman pull redis:latest
podman run -v ./infrastructure/config:/usr/local/etc/redis -p 6379:6379 --name secure_redis_iam redis redis-server /usr/local/etc/redis/redis_insecure.conf
```

### FastAPI Server Setup

```bash
pip install -r requirements.in
python main.py
```

---

## ⚙️ Configuration & Notes

- Ensure `requirements.txt` is encoded as **UTF-8** when using security auditors
- Manually delete/update packages as needed after vulnerability scans
- Always prefer the **secure deployment method** for production environments