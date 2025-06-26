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
import mimetypes
from flask import (
    Blueprint, render_template, request, session, send_from_directory, redirect, url_for, flash, current_app as app
)
from flask_login import login_user, logout_user, login_required
from app_config.config import ConfService as cfgserv
from model.user_service import UserService
import qtsp_client, sca_client
from cryptography.x509.oid import _SIG_OIDS_TO_HASH 
from cryptography.hazmat._oid import ObjectIdentifier


rp = Blueprint("RP", __name__, url_prefix="/")
rp.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')

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

@rp.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', redirect_url = cfgserv.service_url) 

@rp.route('/tester', methods=['GET'])
def main():
    app.logger.info('Load main page.')
    return render_template('main.html', redirect_url= cfgserv.service_url)

@rp.route('/tester/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        app.logger.info('Login request received.')
        username = request.form['username']
        password = request.form['password']
        user = UserService.login(username, password)
        if user is not None:
            app.logger.info('Login successful.')
            login_user(user)
            return redirect(url_for('RP.account'))
        else:
            app.logger.info('Login failed.')
            flash('Login failed! Please check your username and password.')
    users = UserService.get_users()
    return render_template('login.html', redirect_url= cfgserv.service_url, rp_users = users)

@rp.route('/tester/logout')
@login_required
def logout():
    app.logger.info('Logout request received.')
    logout_user()
    app.logger.info('Logout successful.')
    return redirect(url_for('RP.login'))

@rp.route('/tester/account', methods=['GET', 'POST'])
@login_required
def account():
    app.logger.info('Load account page.')
    return render_template('account.html', redirect_url= cfgserv.service_url)

@rp.route('/tester/select_document', methods=['GET'])
@login_required
def select_document():
    app.logger.info("Load select_document page.")
    return render_template('select_document.html', redirect_url= cfgserv.service_url)

# Obtain Access Token with scope="service"
# If not authenticated redirects to authentication page
@rp.route('/tester/service_authorization', methods=['GET'])
@login_required
def service_authorization():
    app.logger.info("Request for service authorization with parameters: "+str(len(request.args)))
    app.logger.info("Document in args: "+request.args.get('document'))
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
    app.logger.info("Filename Choosen: "+filename)
        
    # makes the oauth2/authorize request:
    try:
        app.logger.info("Requesting service authorization.")
        code_verifier, location = qtsp_client.oauth2_authorize_service_request()
        update_session_values(variable_name="code_verifier", variable_value=code_verifier)
        app.logger.info("Received Service Authentication in URL: "+location)
        return redirect(location)
    except ValueError as e:
        app.logger.error("Error in service authorization: "+str(e))
        return str(e), 400

# endpoint where the qtsp will be redirected to after authentication
# used
@rp.route("/tester/oauth2/callback", methods=["GET", "POST"])
def oauth_login_code():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    error_description=request.args.get("error_description")
    
    app.logger.info("Received request with code: %s and state: %s", code, state)
    
    if error:
        app.logger.error("Received Error %s: %s", error, error_description)
        return error_description, 400
    
    code_verifier = session.get("code_verifier")
    if code_verifier is None:
        app.logger.error("Session key 'code_verifier' is missing.")
        return "Session expired or invalid request.", 400
    
    if code is None:
        app.logger.error("No authorization code received.")
        return "Missing authorization code.", 400
        
    try:
        app.logger.info("Requesting token with code: %s and code_verifier: %s", code, code_verifier)
        scope, access_token = qtsp_client.oauth2_token_request(code, code_verifier) # trades the code for the access token
    except ValueError as e:
        app.logger.error("Error during OAuth token request: %s", str(e), exc_info=True)
        return "OAuth token request failed.", 500
    
    if scope == "service":
        remove_session_values(variable_name="code_verifier")
        update_session_values(variable_name="service_access_token", variable_value=access_token)
        return redirect(url_for("RP.credentials_list"))
    elif scope == "credential":
        remove_session_values(variable_name="code_verifier")
        update_session_values(variable_name="credential_access_token", variable_value=access_token)
        return redirect(url_for("RP.sign_document"))
    
    app.logger.error("Unexpected scope received: %s", scope)
    return "Invalid scope received.", 400
     
        
@rp.route("/tester/credentials_list", methods=["GET", "POST"])
@login_required
def credentials_list():
    service_access_token = session.get("service_access_token")
    credentials_ids_list = qtsp_client.csc_v2_credentials_list(service_access_token)
    return render_template('credential.html', redirect_url=cfgserv.service_url, credentials=credentials_ids_list)

@rp.route("/tester/set_credential_id", methods=["GET", "POST"])
def setCredentialId():
    credentialId = request.get_json().get("credentialID")
    app.logger.info("Selected credential: "+credentialId)
    update_session_values(variable_name="credentialID", variable_value=credentialId)

    app.logger.info("Requesting information about the selected credential.")
    service_access_token = session.get("service_access_token")
    _, key_algos = qtsp_client.csc_v2_credentials_info(service_access_token, credentialId)
    update_session_values(variable_name="key_algos", variable_value=key_algos)
    
    return "success"

# Present page with signing options
@rp.route('/tester/check_options')
@login_required
def check():
    filename = session.get("filename")
    signature_format_name, signature_format_value = get_signature_format(filename)
    
    key_algos = session.get("key_algos")
    hash_algos = []
    for algo in key_algos:
        hash_algo = _SIG_OIDS_TO_HASH.get(ObjectIdentifier(algo))
        if hash_algo is not None:
            hash_algos.append({"name":hash_algo.name.upper(), "oid":DIGEST_OIDS.get(hash_algo.name.lower())})
    
    remove_session_values(variable_name="key_algos")
    
    return render_template(
        'select_options.html', redirect_url=cfgserv.service_url, 
        filename=filename, signature_format_name=signature_format_name,
        signature_format_value=signature_format_value, digest_algorithms=hash_algos)

def get_signature_format(filename):
    if filename.endswith('.pdf'):
        return 'PAdES', 'P'
    elif filename.endswith('.xml'):
        return 'XAdES', 'X'
    elif filename.endswith('.json'):
        return 'JAdES', 'J'
    else:
        return 'CAdES', 'C'

# Retrieve document with given name
@rp.route('/docs/<path:filename>')
def serve_docs(filename):
    return send_from_directory('docs', filename)

@rp.route("/tester/signature", methods=['GET', 'POST'])
def sca_signature_flow():
    # saves the form to the session:
    form_local= request.form

    filename = form_local["filename"]
    if not filename:
        return "Filename is required", 400  # Return an error if filename is None
    app.logger.info("Signing File: "+filename)
    update_session_values(variable_name="filename", variable_value=filename)

    base64_document=get_base64_document(filename)
    container=form_local["container"]
    update_session_values(variable_name="container", variable_value=container)
    
    signature_format=form_local["signature_format"]
    signed_envelope_property=form_local["packaging"]
    conformance_level=form_local["level"]
    hash_algorithm_oid=form_local["digest_algorithm"]        
    
    credentialId = session.get("credentialID")

    try:
        location = sca_client.signature_flow(session.get("service_access_token"), credentialId, filename, 
            base64_document, signature_format, conformance_level, signed_envelope_property, 
            container, hash_algorithm_oid)
        app.logger.info("Redirecting to QTSP OID4VP Authentication Page.")
        remove_session_values(variable_name="credentialID")
        return redirect(location)
    except ValueError as e:
        app.logger.error("Error in signature flow: "+str(e))
        return str(e), 400


@rp.route("/tester/signed_document_download", methods=['GET', 'POST'])
def signed_document_download():
    app.logger.info("Received Request with Signed Document.")
    signed_document = request.form["signed_document"]
    app.logger.info("Signed Document present? "+str(signed_document is not None))
            
    filename = session.get("filename")
    if not filename:
        return "Filename is required", 400 # Return an error if filename is None
    app.logger.info("Identified signed document of file: "+filename)
        
    ext = None
    container = session.get("container")
    app.logger.info("Identifying mime_type for container type: "+ container)
    if container == "ASiC-S":
        mime_type = "application/vnd.etsi.asic-s+zip"
        ext = ".zip"
    elif container == "ASiC-E":
        mime_type = "application/vnd.etsi.asic-e+zip"
        ext = ".zip"
    else:
        mime_type, _ = mimetypes.guess_type(filename)

    new_name = add_suffix_to_filename(os.path.basename(filename), new_ext=ext)
    
    remove_session_values(variable_name="filename")
    remove_session_values(variable_name="container")
    
    return render_template(
        'sign_document.html',
        redirect_url=cfgserv.service_url, 
        document_signed_value=signed_document,
        document_content_type=mime_type,
        document_filename=new_name
    )

def update_session_values(variable_name, variable_value):
    if session.get(variable_name) is not None:
        session.pop(variable_name)
    session[variable_name] = variable_value

def remove_session_values(variable_name):
    if session.get(variable_name) is not None:
        session.pop(variable_name)

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

def add_suffix_to_filename(filename, suffix="_signed", new_ext = None):
    name, ext = os.path.splitext(filename)
    
    if new_ext is not None:
        return f"{name}{suffix}{new_ext}"

    return f"{name}{suffix}{ext}"