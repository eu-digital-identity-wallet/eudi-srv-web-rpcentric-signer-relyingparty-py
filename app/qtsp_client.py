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

import requests, secrets, hashlib
from app_config.config import ConfService as cfgserv
import json
import base64
from flask import (
    current_app as app
)

# Request to Authorization Server

# Function that executes the /oauth2/authorize request
# It can either return a 302 response (to a authentication endpoint or the redirect uri endpoint)
# It can return error
def oauth2_authorize_service_request():
    app.logger.info("Requesting authorization to the AS :"+cfgserv.as_url)
    
    code_verifier = secrets.token_urlsafe(32)   
    code_challenge_method = "S256"
    code_challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).rstrip(b'=').decode()
        
    url = cfgserv.as_url+"/oauth2/authorize"
    params = {
        "response_type":"code",
        "client_id": cfgserv.oauth2_client_id,
        "redirect_uri": cfgserv.oauth2_redirect_uri,
        "scope":"service",
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "state": "12345678"
    }
    response = requests.get(url = url, params = params, allow_redirects = False)
    app.logger.info("Received response with status code: "+str(response.status_code))
    
    if response.status_code == 400:
        message = response.json()["message"]
        app.logger.error(message)
        raise ValueError("It was impossible to retrieve the authentication link: "+message)
    elif response.status_code == 200:
        app.logger.info("Successful Response: "+response.text)
        return code_verifier, response
    elif response.status_code == 302:
        location = response.headers["Location"]
        return code_verifier, location
    return response

def oauth2_authorize_credential_request(code_challenge, code_challenge_method, num_signatures, hashes, hash_algorithm_oid, credential_id):
    url = cfgserv.as_url+"/oauth2/authorize?response_type=code&client_id="+cfgserv.oauth2_client_id+"&redirect_uri=" + cfgserv.oauth2_redirect_uri+"&scope=credential&code_challenge="+code_challenge+"&code_challenge_method="+code_challenge_method+"&state=12345678&numSignatures=1&hashes="+hashes+"&hashAlgorithmOID="+hash_algorithm_oid+"&credentialID="+credential_id
    response = requests.get(url=url, allow_redirects=False)
    app.logger.info("Response from oauth2/authorize request: ("+ str(response.status_code)+") "+response.text)
    return response

def oauth2_token_request(code, code_verifier):
    url =  cfgserv.as_url+"/oauth2/token"
        
    value_to_encode = f"{cfgserv.oauth2_client_id}:{cfgserv.oauth2_client_secret}"
    encoded_value = base64.b64encode(value_to_encode.encode()).decode('utf-8')
    authorization_basic = f"Basic {encoded_value}"
    headers= {
        'Authorization': authorization_basic
    }
    
    params = {
        "grant_type":"authorization_code",
        "code": code,
        "client_id": cfgserv.oauth2_client_id,
        "redirect_uri": cfgserv.oauth2_redirect_uri,
        "code_verifier": code_verifier
    }
    
    app.logger.info("Requesting token with params: "+str(params))
    response = requests.post(url = url, params = params, headers = headers, allow_redirects = False)
    app.logger.info("Response: "+str(response))
    
    if response.status_code == 400:
        app.logger.error("It wasn't possible to complete the token request.")
        error = response.json()["error"]
        error_description = response.json()["error_description"]
        app.logger.error("Error in token request: "+error+" - "+error_description)
        raise ValueError("Error while trying to retrieve access: "+error+" - "+error_description)
    
    elif response.status_code == 200:
        app.logger.info("Successful oauth2 token request.")
        response_json = response.json()
        access_token = response_json["access_token"]
        scope = response_json["scope"]
        app.logger.info("Received access token "+access_token+" of scope "+scope)
        return scope, access_token

# Request to Resource Server
def csc_v2_credentials_list(access_token):
    app.logger.info("Requesting credentials list from the QTSP RS: "+cfgserv.rs_url)
    
    url =  cfgserv.rs_url+"/csc/v2/credentials/list"
    
    authorization_header = "Bearer "+access_token
    headers = {
        'Content-Type': 'application/json', 
        'Authorization': authorization_header
    }
    
    payload = json.dumps({
        "credentialInfo": "true",
        "certificates": "single",
        "certInfo": "true"
    })
    
    response = requests.post(url = url, data=payload, headers = headers)     
    
    if response.status_code == 400:
        app.logger.error("Error retrieving credentials list from QTSP RS.")
        message = response.json()["message"]
        app.logger.error(message)
        raise ValueError("It was impossible to retrieve the credentials list from the QTSP: "+message)
    
    elif response.status_code == 200:
        app.logger.info("Retrieved credentials list from QTSP RS.")
        list_credentials_ids = response.json()["credentialIDs"]
        app.logger.info("Retrieved list of credentials ids.")
        return list_credentials_ids

def csc_v2_credentials_info(access_token, credentialId):
    app.logger.info("Requesting credential info from the QTSP RS: "+cfgserv.rs_url)
    url =  cfgserv.rs_url+"/csc/v2/credentials/info"
    
    authorization_header = "Bearer "+access_token
    headers = {
        'Content-Type': 'application/json', 
        'Authorization': authorization_header
    }
    
    payload = json.dumps({
        "credentialID": credentialId,
        "credentialInfo": "true",
        "certificates": "chain",
        "certInfo": "true"
    })
    
    app.logger.info("Requesting credential info with payload: "+payload)
    response = requests.post(url = url, data=payload, headers = headers)
    
    if response.status_code == 400:
        message = response.json()["message"]
        app.logger.error(message)
        raise ValueError("It was impossible to retrieve the credential info from QTSP: "+message)
    
    elif response.status_code == 200:
        credential_info_json = response.json()
        certificates = credential_info_json["cert"]["certificates"]
        key_info = credential_info_json["key"]
        key_algos = key_info["algo"]
        app.logger.info("Retrieved credential info of credential: "+credentialId)
        return certificates, key_algos
        
    return response
