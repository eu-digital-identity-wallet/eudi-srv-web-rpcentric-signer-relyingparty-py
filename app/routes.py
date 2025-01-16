# coding: latin-1
###############################################################################
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
###############################################################################

import os
import base64
import hashlib
import secrets
import mimetypes
from flask import (
    Blueprint, render_template, request, session, send_from_directory, redirect, url_for, flash
)
from flask_login import login_user, logout_user, login_required
from app_config.config import ConfService as cfgserv
from model.user_service import UserService
import qtsp_client, sca_client
from cryptography.x509.oid import _SIG_OIDS_TO_HASH 
from cryptography.hazmat._oid import ObjectIdentifier


sca = Blueprint("SCA", __name__, url_prefix="/")
sca.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')

DIGEST_OIDS = {
    "md5": "1.2.840.113549.2.5",
    "sha1": "1.3.14.3.2.26",
    "sha224": "2.16.840.1.101.3.4.2.4",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
    "sha3_224": "2.16.840.1.101.3.4.2.7",
    "sha3_256": "2.16.840.1.101.3.4.2.8",
    "sha3_384": "2.16.840.1.101.3.4.2.9",
    "sha3_512": "2.16.840.1.101.3.4.2.10",
}

@sca.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', redirect_url = cfgserv.service_url) 

@sca.route('/tester', methods=['GET', 'POST'])
def main():
    return render_template('main.html', redirect_url= cfgserv.service_url)

########

@sca.route('/tester/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = UserService.login(username, password)
        if(user is not None):
            login_user(user)
            return redirect(url_for('SCA.account'))
        else:
            flash('Login failed! Please check your username and password.')
    users = UserService.get_users()
    return render_template('login.html', redirect_url= cfgserv.service_url, rp_users = users)

@sca.route('/tester/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('SCA.login'))

@sca.route('/tester/account', methods=['GET', 'POST'])
@login_required
def account():
    return render_template('account.html', redirect_url= cfgserv.service_url)

########
@sca.route('/tester/select_document', methods=['GET'])
@login_required
def select_document():
    return render_template('select_document.html', redirect_url= cfgserv.service_url)

# Obtain Access Token with scope="service"
# If not authenticated redirects to authentication page
@sca.route('/tester/service_authorization', methods=['GET'])
@login_required
def service_authorization():
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
        
    update_session_values(variable_name="filename", variable_value=filename)
        
    # makes the oauth2/authorize request:
    code_verifier = secrets.token_urlsafe(32)   
    code_challenge_method = "S256"
    code_challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).rstrip(b'=').decode()
    
    update_session_values(variable_name="code_verifier", variable_value=code_verifier)
    
    response = qtsp_client.oauth2_authorize_service_request(code_challenge, code_challenge_method)
    
    if(response.status_code == 302): # redirects to the QTSP OID4VP Authentication Page
        location = response.headers.get("Location")
        return redirect(location)
    else:
        message = response.json()["message"]
        return message, 400

# endpoint where the qtsp will be redirected to after authentication
# used
@sca.route("/tester/oauth2/callback", methods=["GET", "POST"])
def oauth_login_code():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    print(f"Error: {error}")
    error_description=request.args.get("error_description")
    print(f"Error Description: {error_description}")

    code_verifier = session["code_verifier"]
    
    if(code == None):
        return error_description, 400
    else:
        response = qtsp_client.oauth2_token_request(code, code_verifier) # trades the code for the access token
        
        if(response.status_code == 400):
            error = response.json()["error"]
            error_description = response.json()["error_description"]
            return error_description
        elif(response.status_code == 200):
            response_json = response.json()
            
            access_token = response_json["access_token"]
            scope = response_json["scope"]
            
            if(scope == "service"):
                session["service_access_token"] = access_token
                return redirect(url_for("SCA.credentials_list"))
            elif(scope == "credential"):
                session["credential_access_token"] = access_token
                return redirect(url_for("SCA.sign_document"))

@sca.route("/tester/credentials_list", methods=["GET", "POST"])
@login_required
def credentials_list():
    response = qtsp_client.csc_v2_credentials_list(session["service_access_token"])
    credentials = response.json()
    credentials_ids_list = credentials["credentialIDs"]
    return render_template('credential.html', redirect_url=cfgserv.service_url, credentials=credentials_ids_list)

@sca.route("/tester/set_credential_id", methods=["GET", "POST"])
def setCredentialId():
    update_session_values(variable_name="credentialChosen", variable_value=request.get_json().get("credentialID"))

    credential_info = qtsp_client.csc_v2_credentials_info(session["service_access_token"], session["credentialChosen"])

    if credential_info.status_code == 200:
        credential_info_json = credential_info.json()
        
        certificate_info = credential_info_json["cert"]
        certificates = certificate_info["certificates"]
        key_info = credential_info_json["key"]
        key_algos = key_info["algo"]
                
        update_session_values(variable_name="end_entity_certificate", variable_value=certificates[0])
        update_session_values(variable_name="certificate_chain", variable_value=certificates[1])
        update_session_values(variable_name="key_algos", variable_value=key_algos)
    return "success"

# Present page with signing options
@sca.route('/tester/check_options')
@login_required
def check():
    filename = session["filename"]
    signature_format = get_signature_format(filename)
    
    key_algos = session["key_algos"]
    hash_algos = []
    for algo in key_algos:
        hash_algo = _SIG_OIDS_TO_HASH.get(ObjectIdentifier(algo))
        if(hash_algo is not None):
            hash_algos.append({"name":hash_algo.name.upper(), "oid":DIGEST_OIDS.get(hash_algo.name.lower())})
        
    return render_template('select_options.html', redirect_url=cfgserv.service_url, filename=filename, signature_format=signature_format, digest_algorithms=hash_algos)

def get_signature_format(filename):
    if filename.endswith('.pdf'):
        return 'PAdES'
    elif filename.endswith('.xml'):
        return 'XAdES'
    elif filename.endswith('.json'):
        return 'JAdES'
    else:
        return 'CAdES'
    
def get_signature_format_simplified(signature_format):
    if signature_format == "PAdES":
        return 'P'
    elif signature_format == "XAdES":
        return 'X'
    elif signature_format == "JAdES":
        return 'J'
    else:
        return 'C'

# Retrieve document with given name
@sca.route('/docs/<path:filename>')
def serve_docs(filename):
    return send_from_directory('docs', filename)

@sca.route("/tester/signature", methods=['GET', 'POST'])
def sca_signature_flow():
    # saves the form to the session:
    form_local= request.form
        
    update_session_values(variable_name="form_global", variable_value=form_local)

    filename = form_local["filename"]
    # Check if the filename is provided
    if not filename:
        return "Filename is required", 400  # Return an error if filename is None

    base64_document = get_base64_document(filename)
    container=form_local["container"]
    
    signature_format=get_signature_format_simplified(form_local["signature_format"])
    signed_envelope_property= form_local["packaging"]
    conformance_level= form_local["level"]
    hash_algorithm_oid=form_local["digest_algorithm"]        

    authorization_header = "Bearer " + session["service_access_token"]
    credentialId = session["credentialChosen"]

    response = sca_client.signature_flow(authorization_header, credentialId, 
            base64_document, signature_format, conformance_level, signed_envelope_property, 
            container, hash_algorithm_oid)

    if(response.status_code == 302): # redirects to the QTSP OID4VP Authentication Page
        location = response.headers.get("Location")
        return redirect(location)
    else:
        message = response.json()["message"]
        return message, 400

@sca.route("/tester/signed_document_download", methods=['GET', 'POST'])
def signed_document_download():
    
    signed_document = request.form["signed_document"]
    
    # Get the form data
    form_local = session["form_global"]
        
    filename = form_local["filename"]
    if not filename:
        return "Filename is required", 400 # Return an error if filename is None
    
    signed_document_base64 = signed_document
    
    new_name = add_suffix_to_filename(os.path.basename(filename))
    mime_type, _ = mimetypes.guess_type(filename)
    
    return render_template(
        'sign_document.html',
        redirect_url=cfgserv.service_url, 
        document_signed_value=signed_document_base64,
        document_content_type=mime_type,
        document_filename=new_name
    )

def update_session_values(variable_name, variable_value):
    if(session.get(variable_name) is not None):
        session.pop(variable_name)
    session[variable_name] = variable_value


def get_base64_document(filename):
    # Construct the path to the file in the "docs" folder
    file_path = os.path.join(cfgserv.LOAD_FOLDER, filename)

    # Check if the file exists before trying to read it
    if not os.path.isfile(file_path):
        return f"File '{filename}' not found in the docs directory", 404
    
    # Read the content of the file to encode it in base64
    base64_document = None
    with open(file_path, 'rb') as document:
        base64_document = base64.b64encode(document.read()).decode("utf-8")
    
    return base64_document


def add_suffix_to_filename(filename, suffix="_signed"):
    name, ext = os.path.splitext(filename)
    return f"{name}{suffix}{ext}"