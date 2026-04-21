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

import mimetypes, base64, os
from flask import Blueprint, render_template, current_app as app, request, redirect, url_for, flash, session, send_from_directory
from flask_login import login_user, logout_user, login_required
from app.core.config import settings
from app.model.session_state import SessionState
from app.model.user_service import UserService
from app import qtsp_client, sca_client
from cryptography.x509.oid import _SIG_OIDS_TO_HASH 
from cryptography.hazmat._oid import ObjectIdentifier

rp = Blueprint("RP", __name__, url_prefix="/")
rp.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template/')

@rp.route('/', methods=['GET', 'POST'])
def landing():
    return render_template('landing.html', service_url = settings.SERVICE_URL)

@rp.route('/tester', methods=['GET'])
def home():
    return render_template('home.html')

@rp.route('/tester/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = UserService.login(username, password)
        if user is not None:
            login_user(user)
            return redirect(url_for('RP.account'))
        else:
            flash('Login failed! Please check your username and password.')
    users = UserService.get_users()
    return render_template('user-login.html', redirect_url= settings.SERVICE_URL, rp_users = users)

@rp.route('/tester/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('RP.login'))

@rp.route('/tester/account', methods=['GET', 'POST'])
@login_required
def account():
    return render_template('user-account.html', redirect_url= settings.SERVICE_URL)

@rp.route('/tester/document/select', methods=['GET'])
@login_required
def select_document():
    return render_template('document-select.html')


@rp.route('/tester/certificate/options', methods=['GET'])
@login_required
def options_certificate():
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

    update_session_values(variable_name=SessionState.FILENAME, variable_value=filename)
    app.logger.info("Filename chosen: " + filename)
    return render_template('certificate-retrieve-options.html', redirect_url= settings.SERVICE_URL)

@rp.route('/tester/service_authorization', methods=['GET'])
@login_required
def service_authorization():
    try:
        app.logger.info("Requesting service authorization.")
        code_verifier, location = qtsp_client.oauth2_authorize_service_request()
        update_session_values(variable_name=SessionState.CODE_VERIFIER, variable_value=code_verifier)
        app.logger.info("Received Service Authentication in URL: "+location)
        session.modified = True
        return redirect(location)
    except ValueError as e:
        app.logger.error("Error in service authorization: "+str(e))
        return str(e), 400

@rp.route('/tester/create_credential_authorization', methods=['GET'])
@login_required
def create_credential_authorization():
    try:
        app.logger.info("Requesting service authorization.")
        code_verifier, location = qtsp_client.oauth2_authorize_credential_create_request()
        update_session_values(variable_name=SessionState.CODE_VERIFIER, variable_value=code_verifier)
        app.logger.info("Received Service Authentication in URL: "+location)
        session.modified = True
        return redirect(location)
    except ValueError as e:
        app.logger.error("Error in service authorization: "+str(e))
        return str(e), 400

@rp.route("/tester/oauth2/callback", methods=["GET"])
def oauth_login_code():
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    error_description=request.args.get("error_description")
    
    app.logger.info("Received request with code: %s and state: %s", code, state)
    
    if error:
        app.logger.error("Received Error %s: %s", error, error_description)
        return error_description, 400

    
    code_verifier = session.get(SessionState.CODE_VERIFIER)
    if code_verifier is None:
        app.logger.error("Session key 'code_verifier' is missing.")
        return "Session expired or invalid request.", 400
    
    if code is None:
        app.logger.error("No authorization code received.")
        return "Missing authorization code.", 400
        
    try:
        app.logger.info("Requesting token with code: %s and code_verifier: %s", code, code_verifier)
        response = qtsp_client.oauth2_token_request(code, code_verifier) # trades the code for the access token
    except ValueError as e:
        app.logger.error("Error during OAuth token request: %s", str(e), exc_info=True)
        return "OAuth token request failed.", 500

    if response.scope == "service":
        remove_session_values(variable_name=SessionState.CODE_VERIFIER)
        update_session_values(variable_name=SessionState.CREDENTIAL_LIST_ACCESS_TOKEN, variable_value=response.access_token)
        return redirect(url_for("RP.credentials_list"))
    elif response.scope == "credential_creation":
        remove_session_values(variable_name=SessionState.CODE_VERIFIER)
        qtsp_client.csc_v2_credentials_create(response.access_token)
        update_session_values(variable_name=SessionState.CREDENTIAL_LIST_ACCESS_TOKEN, variable_value=response.access_token)
        return redirect(url_for("RP.credentials_list"))
    elif response.scope == "credential_deletion":
        remove_session_values(variable_name=SessionState.CODE_VERIFIER)
        credential_id = session.get(SessionState.CERTIFICATE_ID)
        qtsp_client.csc_v2_credentials_delete(response.access_token, credential_id)
        return redirect(url_for("RP.account"))


    app.logger.error("Unexpected scope received: %s", response.scope)
    return "Invalid scope received.", 400
     
        
@rp.route("/tester/credentials_list", methods=["GET", "POST"])
@login_required
def credentials_list():
    service_access_token = session.get(SessionState.CREDENTIAL_LIST_ACCESS_TOKEN)
    credentials_ids_list = qtsp_client.csc_v2_credentials_list(service_access_token)
    update_session_values(SessionState.LIST_CERTIFICATE_ID, credentials_ids_list.credential_ids)
    return render_template('certificate-list.html', redirect_url=settings.SERVICE_URL, credentials=credentials_ids_list.credential_ids)

@rp.route("/tester/set_credential_id", methods=["GET", "POST"])
def setCredentialId():
    credentialId = request.get_json().get("credentialID")
    app.logger.info("Selected credential: "+credentialId)
    update_session_values(variable_name=SessionState.CERTIFICATE_ID, variable_value=credentialId)
    return "success"

# Present page with signing options
@rp.route('/tester/check_options')
@login_required
def check():
    credentialId = session.get(SessionState.CERTIFICATE_ID)
    app.logger.info("Requesting information about the selected credential.")
    service_access_token = session.get(SessionState.CREDENTIAL_LIST_ACCESS_TOKEN)
    _, key_algos = qtsp_client.csc_v2_credentials_info(service_access_token, credentialId)
    update_session_values(variable_name=SessionState.KEY_ALGOS, variable_value=key_algos)

    filename = session.get(SessionState.FILENAME)
    signature_format_name, signature_format_value = get_signature_format(filename)
    
    key_algos = session.get(SessionState.KEY_ALGOS)
    hash_algos = []
    for algo in key_algos:
        hash_algo = _SIG_OIDS_TO_HASH.get(ObjectIdentifier(algo))
        if hash_algo is not None:
            hash_algos.append({"name":hash_algo.name.upper(), "oid":settings.DIGEST_OIDS.get(hash_algo.name.lower())})
    
    remove_session_values(variable_name=SessionState.KEY_ALGOS)
    
    return render_template(
        'document-options.html', redirect_url=settings.SERVICE_URL,
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
    return send_from_directory(settings.SAMPLE_DOCUMENTS_FOLDER, filename)

@rp.route("/tester/signature", methods=['GET', 'POST'])
def sca_signature_flow():
    # saves the form to the session:
    form_local= request.form

    filename = form_local["filename"]
    if not filename:
        return "Filename is required", 400  # Return an error if filename is None
    app.logger.info("Signing File: "+filename)
    update_session_values(variable_name=SessionState.FILENAME, variable_value=filename)

    base64_document=get_base64_document(filename)
    container=form_local["container"]
    update_session_values(variable_name="container", variable_value=container)
    
    signature_format=form_local["signature_format"]
    signed_envelope_property=form_local["packaging"]
    conformance_level=form_local["level"]
    hash_algorithm_oid=form_local["digest_algorithm"]        
    
    credentialId = session.get(SessionState.CERTIFICATE_ID)

    try:
        location = sca_client.signature_flow(session.get(SessionState.CREDENTIAL_LIST_ACCESS_TOKEN), credentialId, filename,
            base64_document, signature_format, conformance_level, signed_envelope_property, 
            container, hash_algorithm_oid)
        app.logger.info("Redirecting to QTSP OID4VP Authentication Page.")
        remove_session_values(variable_name=SessionState.CERTIFICATE_ID)
        return redirect(location)
    except ValueError as e:
        app.logger.error("Error in signature flow: "+str(e))
        return str(e), 400

@rp.route("/tester/signed_document_download", methods=['GET', 'POST'])
def signed_document_download():
    app.logger.info("Received Request with Signed Document.")
    signed_document = request.form["signed_document"]
    app.logger.info("Signed Document present? "+str(signed_document is not None))
            
    filename = session.get(SessionState.FILENAME)
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
    
    remove_session_values(variable_name=SessionState.FILENAME)
    remove_session_values(variable_name="container")
    
    return render_template(
        'document-signed.html',
        redirect_url=settings.SERVICE_URL,
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
    file_path = os.path.join(settings.SAMPLE_DOCUMENTS_FOLDER, filename)

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

@rp.route('/tester/delete_credential', methods=['GET'])
@login_required
def delete_credential_page():
    credentials_ids = session.get(SessionState.LIST_CERTIFICATE_ID)
    return render_template('certificate-delete.html', redirect_url=settings.SERVICE_URL,
                           credentials=credentials_ids)


@rp.route('/tester/delete_credential_authorization', methods=['GET'])
@login_required
def delete_credential_authorization():
    credential_id = session.get(SessionState.CERTIFICATE_ID)
    try:
        app.logger.info("Requesting service authorization.")
        code_verifier, location = qtsp_client.oauth2_authorize_credential_delete_request(credential_id)
        update_session_values(variable_name=SessionState.CODE_VERIFIER, variable_value=code_verifier)
        app.logger.info("Received Service Authentication in URL: "+location)
        return redirect(location)
    except ValueError as e:
        app.logger.error("Error in service authorization: "+str(e))
        return str(e), 400