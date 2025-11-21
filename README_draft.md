# simple-redis-iam

## DESCRIPTION
The following project constitudes an IAM system constructed based on a redis database and python powerded FastAPI backend service.

Both technologies deliver basic authentication adn authorization methods to manage users access control for the desired web app.

While the services cna be used in deifferent scenarios for different web apps, "The Movie Draft Pick" frontend (link for ) is a open source SPA written in Angular wich can be perfectly used in combination with the folowing repository. 

### GOAL
The principal goal of the project is to show what is good and bad code implementation with regards too the OWASP top 10 2021 (link). Hence, while the code is per default to be configured as secure, additional "insecure" functions, configurations are provided to experiment and showcase the different OWASP vulnerabilities.

## STARTING THE PROJECT

First of all, go to the .env file and add your decired config chnages. Per deffault, we a´have already porvided with working onces. 

ATTENTION: most importantly is the Frontend URL, provide the local/remote URL of your deployed frontend.

### BUILD AND DEPLOY

As bes practice, and to sart showing off the OWASP vulnerbailities, there is two ways to build and deploy the IAM. The two different processes highlight the importance of respecting the A06 and A08 OWASP vulnerbailities: 
    - "A06:2021 – Vulnerable and Outdated Components"
    - "A08:2021 – Software and Data Integrity Failures"

#### SECURE
keep the order of components initialization in mind.

REDIS
    podman/docker

    download redis image & Integrity check
        1. Inspect the remote image without pulling
            # Run Skopeo using Podman/Docker (Cleanest)
            podman run --rm quay.io/skopeo/stable inspect docker://docker.io/library/alpine:latest
        2. Step 2: Pull using the Digest (Not the Tag):
            podman pull docker.io/library/alpine@sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b
        3. Verify Local Integrity: 
            podman inspect --format='{{.Digest}}' alpine

    vulnerability check
        podman run --rm -v trivy_cache:/root/.cache/ aquasec/trivy image redis:latest

    deploy redis container with security config:
        podman run -v ./infrastructure/config:/usr/local/etc/redis -p 6379:6379 --name secure_redis_iam redis redis-server /usr/local/etc/redis/redis.conf


FastAPI SERVER
	# ceck outdated components
	pip list --outdated
	# pretty view
	pip install pip-check
	pip-check
	
	# Install the auditor
	pip install pip-audit uv pip-tools
	# make sure requirements.txt is encoded as UTF-8 to use deptry

	# 🛡️ SECURITY GATE
	# If vulnerabilities are found, this command FAILS (exit 1).
	pip-audit -r requirements.txt --strict --desc

	manually delete/update the desired packages

	# 3.This installs missing packages, uninstalls extra ones (like pandas), removes packages not declared in requirements.txt
	pip-sync
	
	python main.py

#### NOT-SECURE

REDIS
    podman/docker
    
    	podman pull redis:latest
    	podman run -d -p 6379:6379 --name redis_IAM redis

fastAPI server
	pip install requirements.in

	python main.py