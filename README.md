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

1. Set up SSL certificates fo local deployment
2. Configure a Google SMTP service
3. Update the `.env` file with your desired configuration changes. (default settings work without problems)
    - Provide the local/remote URL of your deployed frontend
4. Ensure you have `Docker/Podman` and `Python 3.13` installed

#### Local CA creation

   Install [mkcert](https://github.com/FiloSottile/mkcert) to generate local SSL certificates.

#### Steps:

1. **Install mkcert and create a local CA**
   ```bash
   mkcert -install
   ```
   This creates a new local Certificate Authority (CA).

2. **Generate certificates for your domains**
   ```bash
   mkcert example.com "*.example.com" example.test localhost 127.0.0.1 ::1
   ```
   Certificates will be created for:
   - `example.com`
   - `*.example.com`
   - `example.test`
   - `localhost`
   - `127.0.0.1`
   - `::1`

   The generated files:
   - Public certificate: `./example.com+5.pem`
   - Private key: `./example.com+5-key.pem`

3. **Move certificates to your project**
   Save both files in:  
   `simple-redis-aim/ssl_certs`

4. **Update `.env` configuration**
   Configure SSL paths and domain names accordingly.  
   More details: [Uvicorn HTTPS Deployment](https://uvicorn.dev/deployment/#running-with-https)

---

> **Alternative:** Use [Let’s Encrypt](https://letsencrypt.org/getting-started/) for a global solution.  
Setup is more complex but suitable for production environments.

---

#### 📧 **Setting Up an SMTP Server**

1. **Create an App Password for Your Google Account**  
   Follow Google’s official guide: [Create & use App Passwords](https://support.google.com/accounts/answer/185833?hl=en).  
   This password allows your application to authenticate securely without exposing your main account credentials.

2. **Use Your Email Account as an SMTP Service**  
   With the app password, you can configure your Gmail account as an SMTP server to send emails programmatically.

3. **Learn More**  
   For detailed instructions and examples using Python’s `smtplib`, see:  
   [Mailtrap Blog – Send Email Using smtplib and SMTP](https://mailtrap.io/blog/smtplib/#Send-email-using-smtplib-and-SMTP).

> **Note:** A dummy functional account is already configured in the `.env` file by default.


## 🔧 Build and Deploy

There are two deployment approaches, highlighting the importance of respecting **A06** and **A08** OWASP vulnerabilities:

- **A06:2021** – Vulnerable and Outdated Components
- **A08:2021** – Software and Data Integrity Failures

---

## 🔒 Secure Deployment

Keep the order of components initialization in mind.

### 1️⃣ Redis Setup

#### Step 1: Image Inspection & Integrity Check (using skopeo) https://github.com/containers/skopeo

```bash
podman run --rm quay.io/skopeo/stable inspect docker://docker.io/library/redis:latest
```

#### Step 2: copy the imgae digest (SH2) and Pull Using the Digest

```bash
podman pull docker.io/library/redis@sha256:< DIGEST >
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
pip install pip-check
pip-check
```

#### Step 3: Install Security Auditors

```bash
pip install pip-audit uv pip-tools
```

#### Step 4: Security Gate (Strict Mode)

```bash
pip-audit -r requirements.txt
```
or 
```bash
pip-audit -r requirements.txt --strict --desc
```
for more details about the threat and remediation suggestions.
> ⚠️ **Note:** This command fails (exit 1) if vulnerabilities are found.

#### Step 5: Update & Install dependencies
```bash
pip-sync
```
or
```bash
pip-sync
pip install -r requirements.txt
```

> **Why this is important**: You must make sure to use the ´requirements.txt´ file for this step because it was compiled with package hashes. This ensures that pip verifies the authenticity of every downloaded library against its hash before installing, guaranteeing you get the exact, untampered code you expect.
#### Step 6: Start Service

```bash
python main.py
```

---

## ⚡ Non-Secure Deployment

> ⚠️ **Warning:** This deployment method is **NOT recommended** for production environments.

### Redis Setup

```bash
podman pull redis:latest
podman run -v ./infrastructure/config:/usr/local/etc/redis -p 6379:6379 --name insecure_redis_iam redis redis-server /usr/local/etc/redis/redis_insecure.conf
```

### FastAPI Server Setup

```bash
pip install -r requirements.in
python main.py
```
> **Why is this insecure**: ´requirements.in´ lists dependencies but lacks specific version locks and cryptographic hashes. This creates a significant risk of "dependency spoofing" (installing a malicious package with the same name) or pulling an unexpected, potentially broken version of a library.
---

## ⚙️ Configuration & Notes

- Ensure `requirements.txt` is encoded as **UTF-8** when using security auditors
- Manually delete/update packages as needed after vulnerability scans
- Always prefer the **secure deployment method** for production environments