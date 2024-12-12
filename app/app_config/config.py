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

class ConfService:
    secret_key = "secret_key"

    service_url = "http://127.0.0.1:5000/tester"
    AS="http://localhost:8084"
    RS="http://localhost:8085"
    SCA="http://localhost:8086"
    
    oauth_client_id = "rp-client"
    oauth_client_secret = "relyingpartysecret"
    oauth_redirect_uri = "http://127.0.0.1:5000/tester/oauth2/callback"

    LOAD_FOLDER = 'app/docs' 

    rp_users = [
        {
            'username': 'rp',
            'password': 'pass123',
            'data': 'Seven street'
        },
        {
            'username': 'user1',
            'password': 'pass456',
            'data': 'Nine street'
        }
    ]
