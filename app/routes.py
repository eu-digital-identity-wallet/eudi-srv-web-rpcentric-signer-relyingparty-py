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
from flask_login import login_user, logout_user, login_required, current_user
from app_config.config import ConfService as cfgserv

from model.user_service import UserService
from model.user import User
import qtsp_client, sca_client


sca = Blueprint("SCA", __name__, url_prefix="/")
sca.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')

UPLOAD_FOLDER = 'documents'

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


@sca.route('/tester/select_document', methods=['GET','POST'])
@login_required
def select_document():
    return render_template('select_document.html', redirect_url= cfgserv.service_url)

# Present page with signing options
@sca.route('/tester/check_options')
@login_required
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

# Obtain Access Token with scope="service"
# If not authenticated redirects to authentication page
@sca.route('/tester/service_authorization', methods=['GET', 'POST'])
def service_authorization():
    # saves the form to the session:
    form_local= request.form
    
    if(session.get("form_global") is not None):
        session.pop("form_global")
    
    session["form_global"] = form_local
    
    # makes the oauth2/authorize request:
    code_verifier = secrets.token_urlsafe(32)   
    code_challenge_method = "S256"
    code_challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).rstrip(b'=').decode()
    
    if(session.get("code_verifier") is not None):
        session.pop("code_verifier")
    session["code_verifier"] = code_verifier
    
    response = qtsp_client.oauth2_authorize_service_request(code_challenge, code_challenge_method)
    
    if(response.status_code == 302): # redirects to the QTSP OID4VP Authentication Page
        location = response.headers.get("Location")
        print("Location to authenticate: "+ location)
        return redirect(location)
    else:
        message = response.json()["message"]
        return message, 400

# endpoint where the qtsp will be redirected to after authentication
@sca.route("/tester/oauth2/callback", methods=["GET", "POST"])
def oauth_login_code():
    code = request.args.get("code")
    print(f"Code: {code}")
    state = request.args.get("state")
    print(f"State: {state}")
    error = request.args.get("error")
    print(f"Error: {error}")
    error_description=request.args.get("error_description")
    print(f"Error Description: {error_description}")

    code_verifier = session["code_verifier"]
    print(f"Code Verifier: {code_verifier}")
    
    if(code == None):
        return error_description, 400

    else:
        response = qtsp_client.oauth2_token_request(code, code_verifier) # trades the code for the access token
        print(response.json())
        print(response.status_code)
        
        if(response.status_code == 400):
            error = response.json()["error"]
            error_description = response.json()["error_description"]
            return error_description
        elif(response.status_code == 200):
            response_json = response.json()
            
            access_token = response_json["access_token"]
            print("access token: "+access_token)
            scope = response_json["scope"]
            
            if(scope == "service"):
                session["service_access_token"] = access_token
                return redirect(url_for("SCA.credentials_list"))
            elif(scope == "credential"):
                session["credential_access_token"] = access_token
                return redirect(url_for("SCA.sign_document"))

@sca.route("/tester/credentials_list", methods=["GET", "POST"])
def credentials_list():
    response = qtsp_client.csc_v2_credentials_list(session["service_access_token"])
    credentials = response.json()
    credentials_ids_list = credentials["credentialIDs"]
    print(credentials_ids_list)
    return render_template('credential.html', redirect_url=cfgserv.service_url, credentials=credentials_ids_list)


@sca.route("/tester/set_credential_id", methods=["GET", "POST"])
def setCredentialId():
    if(session.get("credentialChosen") is not None):
        session.pop("credentialChosen")
        
    session["credentialChosen"] = request.get_json().get("credentialID")
    
    credential_info=qtsp_client.csc_v2_credentials_info(session["service_access_token"], session["credentialChosen"])

    if credential_info.status_code == 200:
        credential_info_json = credential_info.json()
        print(credential_info_json["cert"])
        
        certificate_info = credential_info_json["cert"]
        certificates = certificate_info["certificates"]
        print(certificates)
        
        if(session.get("end_entity_certificate") is not None):
            session.pop("end_entity_certificate")
        session["end_entity_certificate"]=certificates[0]
        
        if(session.get("certificate_chain") is not None):
            session.pop("certificate_chain")
        session["certificate_chain"]=certificates[1]
        
        key_info = credential_info_json["key"]
        key_algo = key_info["algo"][0]
        print("Key Algo: "+key_algo)
    return "success"

# Obtain Access Token with scope="credential"
# If not authenticated redirects to authentication page
@sca.route("/tester/credential_authorization", methods=['GET', 'POST'])
def credential_authorization():
    print("Bearer " + session["service_access_token"])
    
    # Get the form data
    form_local = session["form_global"]

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

    calculate_hash_json = sca_client.calculate_hash_request(
        base64_document,
        signature_format,
        conformance_level,
        signed_envelope_property,
        container,
        session["end_entity_certificate"],
        session["certificate_chain"],
        hash_algorithm_oid
    )
    hashes = calculate_hash_json["hashes"]
    if(session.get("hashes") is not None):
        session.pop("hashes")
    session["hashes"] = hashes
    
    print(session["hashes"])
    
    signature_date = calculate_hash_json["signature_date"]
    if(session.get("signature_date") is not None):
        session.pop("signature_date")
    session["signature_date"] = signature_date
   
    code_verifier = secrets.token_urlsafe(32)    
    code_challenge_method = "S256"
    code_challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_bytes).rstrip(b'=').decode()
    
    if(session.get("code_verifier") is not None):
        session.pop("code_verifier")
    session["code_verifier"] = code_verifier
    
    hashes_string = ";".join(hashes)
    print(hashes_string)
    
    response = qtsp_client.oauth2_authorize_credential_request(code_challenge, code_challenge_method, 1, hashes_string, hash_algorithm_oid, session["credentialChosen"])

    if(response.status_code == 302): # redirects to the QTSP OID4VP Authentication Page
        location = response.headers.get("Location")
        print("Location to authenticate: "+ location)
        return redirect(location)
    else:
        message = response.json()["message"]
        return message, 400

@sca.route("/tester/sign_document")
def sign_document():
    
    # Get the form data
    form_local = session["form_global"]
        
    filename = form_local["filename"]
    if not filename:
        return "Filename is required", 400 # Return an error if filename is None

    base64_document = get_base64_document(filename)
    container=form_local["container"]
    signature_format=get_signature_format_simplified(form_local["signature_format"])
    signed_envelope_property= form_local["packaging"]
    conformance_level= form_local["level"]
    hash_algorithm_oid= form_local["digest_algorithm"]

    print(session["hashes"])


    response = qtsp_client.csc_v2_signatures_signHash(
        session["credential_access_token"],
        session["hashes"],
        hash_algorithm_oid, 
        session["credentialChosen"], 
        "1.2.840.10045.2.1"
    )

    signatures = response.json()["signatures"]
    response = sca_client.obtain_signed_document(
        base64_document, 
        signature_format, 
        conformance_level,
        signed_envelope_property, 
        container, 
        session["end_entity_certificate"],
        session["certificate_chain"],
        hash_algorithm_oid, 
        signatures, 
        session["signature_date"]
    )
    
    signed_document_base64 = response.json()["documentWithSignature"][0]
    
    new_name = add_suffix_to_filename(os.path.basename(filename))
    mime_type, _ = mimetypes.guess_type(filename)
    
    return render_template(
        'sign_document.html',
        redirect_url=cfgserv.service_url, 
        document_signed_value=signed_document_base64,
        document_content_type=mime_type,
        document_filename=new_name
    )

@sca.route("/tester/sca_signature_flow", methods=['GET', 'POST'])
def sca_signature_flow():
    print("Bearer " + session["service_access_token"])
    
    # Get the form data
    form_local = session["form_global"]

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
        print("Location to authenticate: "+ location)
        return redirect(location)
    else:
        message = response.json()["message"]
        return message, 400

@sca.route("/tester/signed_document_download", methods=['GET', 'POST'])
def signed_document_download():
    
    signed_document = request.form["signed_document"]
    print(signed_document)
    
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