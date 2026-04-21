# Copyright 2024 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from typing import Tuple

import requests, secrets, hashlib

from app.schemas.csc import *
from app.schemas.oauth2 import *
from app.core.config import settings
import base64
from flask import current_app as app, session


oauth2_authorize_url = settings.AS_URL + "/oauth2/authorize"
oauth2_token_url = settings.AS_URL + "/oauth2/token"
credential_list_endpoint = settings.RS_URL + "/csc/v2/credentials/list"
credential_info_endpoint = settings.RS_URL + "/csc/v2/credentials/info"
credential_create_endpoint = settings.RS_URL + "/csc/v2/credentials/create"
credential_delete_endpoint = settings.RS_URL + "/csc/v2/credentials/delete"

def _get_requests(scope: str, code_challenge: str, authentication: str = None, credential_id: str = None):
    if scope == "service":
        request = OAuth2AuthorizeRequest(
            response_type="code",
            client_id=settings.OAUTH2_CLIENT_ID,
            redirect_uri=settings.oauth2_redirect_uri,
            scope="service",
            code_challenge=code_challenge,
            code_challenge_method=settings.OAUTH2_CODE_CHALLENGE_METHOD,
            state=session.sid
        )
        return request
    elif scope == "credential-creation":
        authorization_details = [{"type": "https://cloudsignatureconsortium.org/2025/credential-creation",
                                  "credentialCreationRequest": {"certificatePolicy": "0.4.0.194112.1.2"}}]
        request = OAuth2AuthorizeRequest(
            response_type="code",
            client_id=settings.OAUTH2_CLIENT_ID,
            redirect_uri=settings.oauth2_redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=settings.OAUTH2_CODE_CHALLENGE_METHOD,
            state=session.sid,
            authorization_details=str(authorization_details)
        )
        return request
    elif scope == "credential-deletion":
        authorization_details = [{"type": "https://cloudsignatureconsortium.org/2025/credential-deletion", "credentialID": credential_id}]
        request = OAuth2AuthorizeRequest(
            response_type="code",
            client_id=settings.OAUTH2_CLIENT_ID,
            redirect_uri=settings.oauth2_redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=settings.OAUTH2_CODE_CHALLENGE_METHOD,
            state=session.sid,
            authorization_details=str(authorization_details)
        )
        return request
    else:
        raise ValueError(f"Unknown scope {scope}")

def _make_oauth2_authorize_request(scope: str, credential_id: str = None) -> Tuple[str, str]:
    app.logger.info(f"Requesting authorization of scope {scope} to {oauth2_authorize_url}")
    
    code_verifier = secrets.token_urlsafe(32)   
    code_challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).rstrip(b'=').decode()

    request = _get_requests(scope=scope, code_challenge=code_challenge, credential_id=credential_id)
    response = requests.get(url = oauth2_authorize_url, params = request.to_params(), allow_redirects = False)
    app.logger.info("Received response with status code: "+str(response.status_code))
    
    if response.status_code == 400:
        message = response.json().get("message")
        app.logger.error("It was impossible to retrieve the authentication link: "+message)
        raise ValueError("It was impossible to retrieve the authentication link: "+message)
    elif response.status_code == 302:
        location = response.headers.get("Location")
        app.logger.info("Retrieved authentication endpoint: " + location)
        return code_verifier, location
    else:
        app.logger.error("Unexpected status code in oauth2/authorize response: " + str(response.status_code))
        raise ValueError("Unexpected status code in oauth2/authorize response: " + str(response.status_code))


def oauth2_authorize_service_request() -> Tuple[str, str]:
    return _make_oauth2_authorize_request(scope = "service")

def oauth2_authorize_credential_create_request() -> Tuple[str, str]:
    return _make_oauth2_authorize_request(scope = "credential-creation")

def oauth2_authorize_credential_delete_request(credential_id:str) -> Tuple[str, str]:
    return _make_oauth2_authorize_request(scope = "credential-deletion", credential_id=credential_id)

def oauth2_token_request(code: str, code_verifier: str) -> OAuth2TokenResponse:
    app.logger.info("Requesting token to:" + oauth2_token_url)
    value_to_encode = f"{settings.OAUTH2_CLIENT_ID}:{settings.OAUTH2_CLIENT_SECRET}"
    encoded_value = base64.b64encode(value_to_encode.encode()).decode('utf-8')
    authorization_basic = f"Basic {encoded_value}"
    headers= {
        'Authorization': authorization_basic
    }

    request = OAuth2TokenRequest(
        grant_type="authorization_code",
        code=code,
        client_id=settings.OAUTH2_CLIENT_ID,
        redirect_uri=settings.oauth2_redirect_uri,
        code_verifier=code_verifier,
    )
    
    response = requests.post(url = oauth2_token_url, params = request.to_params(), headers = headers, allow_redirects = False)
    app.logger.info("Received response with status code: "+str(response.status_code))

    if response.status_code == 400:
        app.logger.error("It wasn't possible to complete the token request.")
        error = response.json().get("error")
        error_description = response.json().get("error_description")
        app.logger.error("Error in token request: "+error+" - "+error_description)
        raise ValueError("Error while trying to retrieve access: "+error+" - "+error_description)
    
    elif response.status_code == 200:
        app.logger.info("Successful oauth2 token response status code: " + str(response.status_code))
        return OAuth2TokenResponse.from_json(response.json())
    else:
        raise ValueError("Unexpected status code (" + str(response.status_code) + ") when trying to retrieve access token.")

# Request to Resource Server
def _get_headers(access_token: str):
    return {
        'Content-Type': 'application/json',
        'Authorization': "Bearer " + access_token
    }

def csc_v2_credentials_list(access_token: str) -> CredentialsListResponse:
    app.logger.info("Requesting credentials list to: " + credential_list_endpoint)

    request = CredentialsListRequest(
        credentialInfo=True,
        certificates="single",
        certInfo=True
    )
    
    headers = _get_headers(access_token)
    response = requests.post(url = credential_list_endpoint, data=request.to_json(), headers = headers)
    
    if response.status_code == 400:
        message = response.json().get("message")
        app.logger.error(message)
        app.logger.error("It was impossible to retrieve the credentials list. " + message)
        raise ValueError("It was impossible to retrieve the credentials list: " + message)
    elif response.status_code == 200:
        app.logger.info("Retrieved credentials list.")
        return CredentialsListResponse.from_json(response.json())
    else:
        app.logger.error("Unexpected status code in credentials/list response: " + str(response.status_code))
        raise ValueError("It was impossible to retrieve the credentials list.")

def csc_v2_credentials_info(access_token: str, credentialId: str) -> Tuple[list[str], list[str]]:
    app.logger.info("Requesting credential info to: " + credential_info_endpoint)

    headers = _get_headers(access_token)

    request = CredentialsInfoRequest(
        credentialID=credentialId,
        certificates="chain",
        certInfo=True
    )
    
    app.logger.info("Requesting credential info with payload: "+request.to_json())
    response = requests.post(url = credential_info_endpoint, data=request.to_json(), headers = headers)
    
    if response.status_code == 400:
        message = response.json().get("message")
        app.logger.error("It was impossible to retrieve the credential info: "+message)
        raise ValueError("It was impossible to retrieve the credential info: "+message)
    
    elif response.status_code == 200:
        info_response = CredentialsInfoResponse.from_json(response.json())
        app.logger.info("Retrieved credential info.")
        return info_response.cert.certificates, info_response.key.algo
        
    else:
        app.logger.error("Unexpected status code in credentials/info response: " + str(response.status_code))
        raise ValueError("It was impossible to retrieve the credential info.")

def csc_v2_credentials_create(access_token: str):
    app.logger.info("Requesting credentials create.")

    headers = _get_headers(access_token)
    credential_creation_request = CredentialCreationRequest(
        certificatePolicy="0.4.0.194112.1.2"
    )
    request = CredentialsCreateRequest(
        credentialCreationRequest=credential_creation_request,
        credentialInfo=True,
        certificates="single",
        certInfo=True
    )

    response = requests.post(url=credential_create_endpoint, data=request.to_json(), headers=headers)

    if response.status_code == 400:
        message = response.json()["message"]
        app.logger.error("It was impossible to create the certificate: " + message)
        raise ValueError("It was impossible to create the certificate: " + message)
    elif response.status_code == 201:
        app.logger.info("Created Certificate.")
    else:
        app.logger.error("Unexpected status code in credentials/create response: " + str(response.status_code))
        raise ValueError("Received an unexpected status code when creating the certificate.")

def csc_v2_credentials_delete(access_token: str, credential_id: str):
    app.logger.info("Requesting credentials delete.")

    headers = _get_headers(access_token)
    request = CredentialsDeleteRequest(
        credentialID=credential_id
    )

    response = requests.post(url=credential_delete_endpoint, data=request.to_json(), headers=headers)
    if response.status_code == 400:
        message = response.json()["message"]
        app.logger.error("It was impossible to delete the certificate: " + message)
        raise ValueError("It was impossible to delete the certificate: " + message)
    elif response.status_code == 204:
        app.logger.info("Deleted Certificate.")
    else:
        app.logger.error("Unexpected status code in credentials/delete response: " + str(response.status_code))
        raise ValueError("Received an unexpected status code when deleting the certificate.")