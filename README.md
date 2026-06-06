# SecureLLM Based Gateway Interface

A FastAPI-based API Gateway that provides request validation, authentication, rate limiting, threat detection, auditing, and request routing for downstream AI services.

The threat detection is fully orchestrated by an LLM based system named SecureLLM, built to ensure that every security breach or malicious content will be spotted immediately right before it's sent to its destination.

## Features

* API key authentication
* Request validation and threat detection based on SecureLLM
* Request and response auditing
* Structured logging and monitoring
* Dockerized deployment
* FastAPI-powered REST interface

## Prerequisites

Before running the gateway, ensure that the following are installed:

* Docker
* Docker Compose

## Running the Gateway

### 1. Clone the Repository

```bash
git clone <repository-url>
cd <repository-folder>
```

### 2. Configure Environment Variables

Create a `.env` file in the project root and populate the required configuration values:

```env
OPENAI_API_KEY=<your-api-key>
MONGO_URL=<mongodb-uri>
REDIS_URL=<redis-url>
```

### 3. Build and Start the Services

```bash
docker-compose up --build
```

To run the services in detached mode:

```bash
docker-compose up -d --build
```

### 4. Verify the Gateway

Once the containers are running, access:

* API: `http://localhost:8000`
* Swagger UI: `http://localhost:8000/docs`
* ReDoc: `http://localhost:8000/redoc`

### 5. Stop the Services

```bash
docker-compose down
```

## Project Structure

```text
.
├── app/
├── llm_configuration
├── unit_tests
├── gw_interface.py
├── defines.py
├── utils.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env
├── .gitleaks.toml
├── PROMPTS.md
└── README.md
```
Here's a quick overview over the project's folder files:
1. gw_interface.py - The main file of the project, contains the fastAPI interface of the gateway combined with SecureLLM class implementation.
2. defines.py - Includes all the const values and setup variables for the project.
3. llm_configuration - A sub folder containing the configuration of the SecureLLM class, including a txt file for the system rule sheet of SecureLLM (secure_llm_rules.txt) and file defining the SecureLLM class itself (secure_llm.py)
4. unit_tests - A sub folder containing unit tests for the SecureLLM scenarios + SecureLLM sub methods.
5. utils.py - File for all utility and helper for the SecureLLM performance and the gateway itself.
6. .env - File for storing environment variables.
7. .gitleaks.toml - A file for scanning the folder's content.
7. Dockerfile, docker-compose.yml, requirements.txt - Running files for the entire interface.
8. PROMPTS.md - An informative file, describing the AI system and prompts that were used for establishing the project.
9. README.md

## Development Notes

The gateway is designed to process incoming requests through the following pipeline:

1. API key authentication
2. Threat and policy checks 
3. Request forwarding 
4. Audit logging 
5. Response delivery

