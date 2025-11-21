# simple-redis-iam

## Description

The following project constitutes an IAM (Identity and Access Management) system built on a Redis database with a Python-powered FastAPI backend service.

Both technologies deliver basic authentication and authorization methods to manage user access control for web applications.

While these services can be used in different scenarios for various web apps, ["The Movie Draft Pick"](https://github.com/DAVEisZERO/movie-draft-pick) frontend is an open-source SPA written in Angular that works perfectly in combination with this repository.

### Goal

The principal goal of this project is to demonstrate good and bad code implementation regarding the [OWASP Top 10 2021](https://owasp.org/Top10/A00_2021_Introduction/). While the code is configured securely by default, additional "insecure" functions and configurations are provided to experiment with and showcase different OWASP vulnerabilities.

---

## Getting Started

### Prerequisites

- Update the `.env` file with your desired configuration changes
- Provide the local/remote URL of your deployed frontend
- Ensure you have `Docker/Podman` and `Python 3.13` installed

> ⚠️ **Note:**  most importantly is the Frontend URL, provide the local/remote URL of your deployed frontend.

### Build and Deploy

There are two deployment approaches, highlighting the importance of respecting **A06** and **A08** OWASP vulnerabilities:
- **A06:2021** – Vulnerable and Outdated Components
- **A08:2021** – Software and Data Integrity Failures

---

## Secure Deployment

Keep the order of components initialization in mind.

### Redis Setup

#### 1. Image Inspection & Integrity Check

```bash
# Inspect the remote image without pulling
podman run --rm quay.io/skopeo/stable inspect docker://docker.io/library/alpine:latest
```

#### 2. Pull Using the Digest

```bash
# Pull using the Digest (not the tag)
podman pull docker.io/library/alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
```

#### 3. Verify Local Integrity

```bash
podman inspect --format='{{.Digest}}' alpine
```

#### 4. Vulnerability Check

```bash
podman run --rm -v trivy_cache:/root/.cache/ aquasec/trivy image redis:latest
```

#### 5. Deploy Redis Container with Security Config

```bash
podman run -v ./infrastructure/config:/usr/local/etc/redis -p 6379:6379 --name secure_redis_iam redis redis-server /usr/local/etc/redis/redis.conf
```

### FastAPI Server Setup

#### 1. Check for Outdated Components

```bash
pip list --outdated
pip install pip-check
pip-check
```

#### 2. Install Security Auditors

```bash
pip install pip-audit uv pip-tools
```

#### 3. Security Gate (Strict Mode)

```bash
pip-audit -r requirements.txt --strict --desc
```

> ⚠️ **Note:** This command fails (exit 1) if vulnerabilities are found.

#### 4. Update Dependencies

```bash
pip-sync
python main.py
```

---

## Non-Secure Deployment

### Redis Setup

```bash
podman pull redis:latest
podman run -d -p 6379:6379 --name redis_IAM redis
```

### FastAPI Server Setup

```bash
pip install -r requirements.txt
python main.py
```

---

## Notes

- Ensure `requirements.txt` is encoded as UTF-8 when using security auditors
- Manually delete/update packages as needed after vulnerability scans
- Always prefer the secure deployment method for production environments