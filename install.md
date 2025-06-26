# Installation

## Local Deployment

### 1. Python

The EUDI RP-Centric Relying Party application was tested with

- Python version 3.10.12

and should only be used with Python 3.10 or higher.

If you don't have it installed, please downlod it from <https://www.python.org/downloads/> and follow the [Python Developer's Guide](https://devguide.python.org/getting-started/).

### 2. Flask

The EUDI RP-Centric Relying Party application was tested with

- Flask v. 2.3

and should only be used with Flask v. 2.3 or higher.

To install [Flask](https://flask.palletsprojects.com/en/2.3.x/), please follow the [Installation Guide](https://flask.palletsprojects.com/en/2.3.x/installation/).

### 3. Running the EUDI RP-Centric Relying Party Application

To run the application, follow these simple steps (some of which may have already been completed when installing Flask) for Linux/macOS or Windows.

#### Step 1: Clone the Repository

Clone the eudi-srv-web-rpcentric-signer-relyingparty-py repository from GitHub:

```shell
git clone git@github.com:eu-digital-identity-wallet/eudi-srv-web-rpcentric-signer-sca-java.git
```

#### Step 2: Create a Virtual Environment

Create a `.venv` folder within the cloned repository:

```shell
cd eudi-srv-web-rpcentric-signer-relyingparty-py
python3 -m venv .venv
```

#### Step 3: Activate the Virtual Environment

Linux/macOS

```shell
. .venv/bin/activate
```

Windows

```shell
. .venv\Scripts\Activate
```

#### Step 4: Upgrade pip

Install or upgrade _pip_

```shell
python -m pip install --upgrade pip
```

#### Step 5: Install Dependencies

Install Flask and other dependencies in virtual environment

```shell
pip install -r app/requirements.txt
```

#### Step 6: Configure the Application

Update the **config.py** file located in the app_config directory or, alternatively, create an **.env** file.
In either case, configure the following variables:

- **secret_key**: define a secure and random key
- **service_url**: the base URL of the service
- **as_url**: the URL of the QTSP Authorization Server (AS)
- **rs_url**: the URL of the QTSP Resource Server (RS)
- **sca_url**: the URL of the RP internal SCA Server
- **oauth2_client_id**: the client ID of the RP Web Page in the QTSP AS
- **oauth2_client_secret**: the client secret of the RP Web Page in the QTSP AS

You may alternatively define all variables in a *.env* file:
```
FLASK_RUN_PORT=
SECRET_KEY=
SERVICE_URL=
AS_URL=
RS_URL=
SCA_URL=
OAUTH2_CLIENT_ID=
OAUTH2_CLIENT_SECRET=
```

#### Step 7: Run the Application

Run the EUDI RP-Centric Relying Party application (on <http://127.0.0.1:5000>)

```shell
flask --app app run
```

## Docker Deployment

You can also deploy the RP-Centric Relying Party using Docker in two ways:

- Use the pre-built image from GitHub Container Registry
- Build the Docker image locally from source

### Requirements

- Docker
- Docker Compose

### Configure .env File

Create a *.env* file in the project root with the following structure:
```shell
FLASK_RUN_PORT=          # Port for the Flask server 
SECRET_KEY=              # A secure and random key
SERVICE_URL=             # the base URL of the service
AS_URL=                  # the URL of the QTSP Authorization Server (AS)
RS_URL=                  # the URL of the QTSP Resource Server (RS)
SCA_URL=                 # the URL of the RP internal SCA Server
OAUTH2_CLIENT_ID=        # the client id of the RP Web Page in the QTSP AS
OAUTH2_CLIENT_SECRET=    # the client secret of the RP Web Page in the QTSP AS
```

### Configure docker-compose.yml

#### Use Pre-Built Image

To use the pre-built image from GitHub, modify your docker-compose.yml as follows:

```
services:
  rpcentric_relyingparty:
    image: ghcr.io/eu-digital-identity-wallet/eudi-srv-web-rpcentric-signer-relyingparty-py:latest
    container_name: rpcentric_relyingparty
    ...
```

#### Optional: Change Port

Optionally, to avoid port conflicts, change the exposed port:

```
ports:
    - "5000:5000" # Change first 5000 if the port is already used
```

### Build and Run with Docker

To start the 'EUDI RP-Centric Relying Party' application as a Docker Container, run the command:
```shell
docker compose up --build
```