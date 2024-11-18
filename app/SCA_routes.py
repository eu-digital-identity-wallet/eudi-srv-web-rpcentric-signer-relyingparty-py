# coding: latin-1
###############################################################################
# Copyright (c) 2023 European Commission
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
###############################################################################

import base64
import json
import os
import mimetypes
from flask import (
    Blueprint,
    render_template,
    request,
    jsonify,
    session,
    send_from_directory,
    redirect,
    url_for,
    flash
)
import os
from flask import Flask, request, session
from werkzeug.utils import secure_filename
import jwt
import requests
from werkzeug.utils import secure_filename
import base64
import secrets
import hashlib
from app_config.config import ConfService as cfgserv

sca = Blueprint("SCA", __name__, url_prefix="/")

sca.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')
UPLOAD_FOLDER = 'documents'
app = Flask(__name__)

@sca.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', redirect_url= cfgserv.service_url)
    

@sca.route('/tester', methods=['GET', 'POST'])
def rp_authentication():
    return render_template('login_rp.html', redirect_url= cfgserv.service_url, rp_users = cfgserv.rp_users)

@sca.route('/tester/rp_login', methods=['GET', 'POST'])
def rp_login():

    username = request.form.get("username")
    password = request.form.get("password")
    
    for user in cfgserv.rp_users:
        if user['username'] == username and user['password'] == password: 
            return redirect(url_for('SCA.select_doc'))
    
    flash('Login failed! Please check your username and password.')
    return render_template('login_rp.html', redirect_url= cfgserv.service_url, rp_users = cfgserv.rp_users)


@sca.route('/tester/qtsp_authentication', methods=['GET', 'POST'])
def qtsp_authentication():
    return render_template('auth.html', redirect_url= cfgserv.service_url)

# starts the authentication process throught the /oauth2/authorize and receives the link to the wallet
@sca.route('/tester/service_authorization', methods=['GET','POST'])
def service_authorization():
    # generate nonce
    session["code_verifier"] = secrets.token_urlsafe(32)
    code_challenge_method = "S256"
    code_challenge_bytes = hashlib.sha256(session["code_verifier"].encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).decode()
    
    # format url-encoded request
    params = {
        "response_type":"code",
        "client_id": cfgserv.oauth_client_id,
        "redirect_uri": cfgserv.oauth_redirect_uri,
        "scope":"service",
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "lang": "pt-PT",
        "state": "12345678"
    }
    uri = cfgserv.AS+"/oauth2/authorize"
    response = requests.get(url = uri, params = params, allow_redirects = False)
    
    # get location to redirect & cookie returned
    print(response.status_code)
    print(response.headers)
    if(response.status_code == 400):
        session.pop("code_verifier")
        message = response.json()["message"]
        return message, 400
    else:
        location = response.headers.get("Location")
        print(location)
        if location.startswith("eudi-openid4vp"):        
            response_json = {"location": location}
            return jsonify(response_json)
        else:
            response = requests.get(url=location)
            return response.text, 400

# endpoint where the qtsp will be redirected to after authentication
@sca.route("/tester/oauth/login/code", methods=["GET", "POST"])
def oauth_login_code():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    error_description=request.args.get("error_description")
    
    # Print the parameters to the console (or handle them as needed)
    print(f"Code: {code}")
    print(f"State: {state}")
    print(f"Error: {error}")
    print(f"Error Description: {error_description}")
    
    if(code != None):
        params = {
            "grant_type":"authorization_code",
            "code": code,
            "client_id": cfgserv.oauth_client_id,
            "redirect_uri": cfgserv.oauth_redirect_uri,
            "code_verifier": session["code_verifier"]
        }
        return executeOAuth2TokenRequest(params=params)
    else:
        # session.pop("code_verifier")
        return error_description

def executeOAuth2TokenRequest(params):
    uri =  cfgserv.AS+"/oauth2/token"
        
    authorization_basic = authorization_value(cfgserv.oauth_client_id, cfgserv.oauth_client_secret)
    headers_a = {'Authorization': authorization_basic}
    
    response = requests.post(url = uri, params = params, headers = headers_a, allow_redirects = False)
    print(response.json())
    print(response.status_code)
    
    if(response.status_code == 400):
        error = response.json()["error"]
        error_description = response.json()["error_description"]
        return error_description
    elif(response.status_code == 200):
        access_token = response.json()["access_token"]
        jwt.decode(access_token, options={"verify_signature": False})
        session["service_access_token"] = access_token
        print("access token: "+access_token)
        return render_template('auth_success.html', redirect_url= cfgserv.service_url, access_token_value=access_token)
    
@sca.route('/tester/credentials_page', methods=['GET', 'POST'])
def credential_page():
    return render_template('credential.html', redirect_url= cfgserv.service_url) 

@sca.route("/tester/credentials_list", methods=["GET", "POST"])
def credentials_list():
    print(session["service_access_token"])
    authorization_header = "Bearer "+session["service_access_token"]
    headers_a = {'Content-Type': 'application/json', 'Authorization': authorization_header}
    payload = json.dumps({
        "credentialInfo": "true",
        "certificates": "single",
        "certInfo": "true"
    })
    uri =  cfgserv.RS+"/csc/v2/credentials/list"
    response = requests.post(url = uri, data=payload, headers = headers_a, allow_redirects = False)
    return response.json()

@sca.route("/tester/set_credentialId", methods=["GET", "POST"])
def setCredentialId():
    session["credentialChosen"] = request.get_json().get("credentialID")
    print(session["credentialChosen"])
    return "success"

@sca.route('/docs/<path:filename>')
def serve_docs(filename):
    return send_from_directory('docs', filename)

@sca.route('/tester/select_document', methods=['GET','POST'])
def select_doc():
    return render_template('select_doc.html', redirect_url= cfgserv.service_url)

def get_signature_format(filename):
    if filename.endswith('.pdf'):
        return 'PAdES'
    elif filename.endswith('.xml'):
        return 'XAdES'
    elif filename.endswith('.json'):
        return 'JAdES'
    else:
        return 'CAdES'

@sca.route('/tester/check')
def check():
    document_type = request.args.get('document')

    if document_type == 'pdf':
        filename = 'sample.pdf'
    elif document_type == 'json':
        filename = 'sample.json'
    elif document_type == 'txt':
        filename = 'sample.txt'
    elif document_type == 'xml':
        filename = 'sample.xml'
    else:
        return "Invalid document type selected."
    
    signature_format = get_signature_format(filename)

    return render_template('select_options.html', redirect_url= cfgserv.service_url, filename = filename, signature_format = signature_format)

@sca.route('/tester/pdf', methods=['GET','POST'])
def pdf():
    return render_template('pdf.html', redirect_url= cfgserv.service_url)

@sca.route("/tester/authorization_credential", methods=["GET", "POST"])
def authorization_credential():
    if request.method == "POST":
        print("Bearer " + session["service_access_token"])

        # Get the form data
        form_local = request.form
        session["form_global"] = form_local

        # Extract the filename from the form
        filename = form_local.get("filename")  # The filename should come from the form

        # Check if the filename is provided
        if not filename:
            return "Filename is required", 400  # Return an error if filename is None

        # Extract other form fields
        container = form_local.get("container")
        signature_format = form_local.get("signature_format")
        packaging = form_local.get("packaging")
        level = form_local.get("level")
        digest_algorithm = form_local.get("digest_algorithm")  # Change "algorithm" to "digest_algorithm"

        # Construct the path to the file in the "docs" folder
        file_path = os.path.join(cfgserv.LOAD_FOLDER, filename)

        # Check if the file exists before trying to read it
        if not os.path.isfile(file_path):
            return f"File '{filename}' not found in the docs directory", 404

        # Read the content of the file to encode it in base64
        with open(file_path, 'rb') as document:
            base64_document = base64.b64encode(document.read()).decode("utf-8")
            print(base64_document)

        # Construct the headers for the request
        headers = {
            "Content-Type": "application/json",
            'Authorization': "Bearer " + session["service_access_token"],
        }

        # Construct the payload with the received data
        payload = {
            "credentialID": session.get("credentialChosen"),
            "numSignatures": "1",
            "documents": [{
                "document": base64_document,
                "signature_format": signature_format[0],
                "conformance_level": level,
                "signed_envelope_property": packaging,
                "container": container
            }],
            "hashAlgorithmOID": digest_algorithm,
            "authorizationServerUrl": cfgserv.AS,
            "resourceServerUrl": cfgserv.RS,
            "clientData": "12345678"
        }

        #return payload

        # URL for the authorization
        uri = cfgserv.SCA + "/credential/authorize"
        response = requests.post(url=uri, headers=headers, data=json.dumps(payload), allow_redirects=False)

        # Process the response
        print(response.json())

        location = response.json().get("location_wallet")
        print(location)
        cookie = response.json().get("session_cookie")
        print(cookie)
        date_l = response.json().get("signature_date")
        print(date_l)

        # Save the date in the session
        session["date"] = date_l
        
        # Render the authorization page with the returned location
        return redirect(url_for('SCA.qtsp_authentication'))
        return render_template('credential_authorization.html', redirect_url=cfgserv.service_url, location=location)

    # If it's not a POST request, return an error message
    return "Invalid request", 405

@sca.route("/tester/oauth/credential/login/code", methods=["GET", "POST"])
def oauth_credential_login_code():
    access_token_form = request.form["access_token"]    
    access_token_form_json = json.loads(access_token_form)    
    access_token = access_token_form_json["access_token"]
    
    session["credential_access_token"] = access_token
    return render_template('credential_authorization_success.html', redirect_url=cfgserv.service_url, access_token_value=access_token)

# Requests to the backend servers
@sca.route('/tester/upload_document', methods=['GET','POST'])
def upload_document():
    form = session["form_global"]
    container=form["container"]
    signature_format= form["signature_format"]
    packaging= form["packaging"]
    level= form["level"]
    digest_algorithm= form["algorithm"]
    print(digest_algorithm)
    
    file_path = session["filename"]
    file = open(file_path, "rb")
    print(os.path.basename(file.name))
    document_content = file.read()
    base64_pdf= base64.b64encode(document_content).decode("utf-8")
    headers ={
        "Content-Type": "application/json",
        'Authorization': "Bearer "+session["credential_access_token"],
    }

    print(session["date"])

    payload = {
        "credentialID": session["credentialChosen"],
        "documents":[{
            "document":base64_pdf,
            "signature_format":signature_format[0],
            "conformance_level": level,
            "signed_envelope_property":packaging,
            "container": container
        }],
        "hashAlgorithmOID": digest_algorithm,
        "request_uri":cfgserv.RS,
        "signature_date": session["date"],
        "clientData": "12345678"
    }
    
    response = requests.request("POST", cfgserv.SCA+"/signatures/signDoc" , headers=headers, data=json.dumps(payload))
    #print(response.json()["documentWithSignature"][0])
    print(os.path.basename(file.name))
    new_name = add_suffix_to_filename(os.path.basename(file.name))
    print(new_name)    
    mime_type, encoding = mimetypes.guess_type(file.name)
    print(mime_type)  
        
    response_json = {
        "document_string": response.json()["documentWithSignature"][0], 
        "filename": new_name, 
        "content_type": mime_type
    }
    
    session.pop("date")
    session.pop("form_global")
    session.pop("credentialChosen")
    session.pop("credential_access_token")
    session.pop("filename")
    os.remove(file_path)
    print(session)
    return jsonify(response_json)
    
def authorization_value(username, password):
    value_to_encode = f"{username}:{password}"
    print(value_to_encode)
    encoded_value = base64.b64encode(value_to_encode.encode()).decode('utf-8')
    print(encoded_value)
    return f"Basic {encoded_value}"

def add_suffix_to_filename(filename, suffix="_signed"):
    # Split the filename into name and extension
    name, ext = os.path.splitext(filename)
    # Add the suffix before the file extension and return the new name
    return f"{name}{suffix}{ext}"
