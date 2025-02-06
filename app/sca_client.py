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

import requests
from app_config.config import ConfService as cfgserv
import json
from flask import (
    current_app as app, url_for
)

def signature_flow(access_token, credentialId, filename, document, signature_format, conformance_level, signed_envelope_property, container, hash_algorithm_oid):
    app.logger.info("Requesting signature to the SCA: "+cfgserv.SCA)
    url = cfgserv.SCA+"/signatures/doc"
    
    redirect_url = cfgserv.service_url+"/signed_document_download"
    
    authorization_header = "Bearer " + access_token
    headers = {
        'Content-Type': 'application/json',
        'Authorization': authorization_header
    }

    payload = json.dumps({
        "credentialID": credentialId,
        "documents": [
            {
                "document": document,
                "document_name": filename,
                "signature_format": signature_format,
                "conformance_level": conformance_level,
                "signed_envelope_property": signed_envelope_property,
                "container": container
            }
        ],
        "hashAlgorithmOID": hash_algorithm_oid,
        "resourceServerUrl": cfgserv.RS,
        "authorizationServerUrl": cfgserv.AS,
        "redirectUri": redirect_url
    })
    
    app.logger.info("Requesting signature with credentialId "+credentialId)

    response = requests.post(url, headers=headers, data=payload, allow_redirects=False)
    app.logger.info("Made Signature Request to SCA. Status Code: "+str(response.status_code))
   
    if(response.status_code == 302): # redirects to the QTSP OID4VP Authentication Page
        app.logger.info("Successfully made request to sign the document. Redirecting to the OID4VP Authentication Page to authorize signature.")
        location = response.headers.get("Location")
        app.logger.info("Redirecting to: "+location)
        return location
    else:
        app.logger.error("It was impossible to sign the document")
        message = response.json()["message"]
        app.logger.error("Error message: "+message)
        raise ValueError("It was impossible to sign the document: "+message) 