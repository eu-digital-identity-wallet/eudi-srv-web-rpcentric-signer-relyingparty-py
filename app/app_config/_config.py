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
"""
This config.py contains configuration data.
"""
import os

class ConfService:
    secret_key = os.getenv("SECRET_KEY") or "secret_here"
    service_url = os.getenv("SERVICE_URL") or "rp_web_page_here"

    as_url="qtsp_as_url_here"
    rs_url="qtsp_rs_url_here"
    sca_url="rp_internal_sca_url_here"
    
    oauth2_client_id = os.getenv("OAUTH2_CLIENT_ID") or "client_id_here"
    oauth2_client_secret = os.getenv("OAUTH2_CLIENT_SECRET") or "client_secret_here"
    oauth2_redirect_uri = service_url+"/oauth2/callback"

    LOAD_FOLDER = 'docs'