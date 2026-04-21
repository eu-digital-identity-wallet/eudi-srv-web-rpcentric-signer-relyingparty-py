# coding: latin-1
###############################################################################
# Copyright (c) 2026 European Commission
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

class SessionState:
    # OAuth2 Values
    CODE_VERIFIER = "code_verifier"
    CODE_CHALLENGE = "code_challenge"

    # Authentication Values
    CREDENTIAL_LIST_ACCESS_TOKEN = "service_access_token"

    # Document Selection Values
    FILENAME = "filename"

    # Certificate Values
    LIST_CERTIFICATE_ID = "credentials_ids_list"
    CERTIFICATE_ID = "credentialID"
    KEY_ALGOS = "key_algos"