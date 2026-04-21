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

import os

"""
This config.py contains configuration data.
"""
class Settings:
    ENV: str = os.getenv("ENV", "dev")
    SECRET_KEY: str = os.getenv("SECRET_KEY")

    SAMPLE_DOCUMENTS_FOLDER: str = os.getenv("SAMPLE_DOCUMENTS_FOLDER")
    LOGS_FOLDER: str = os.getenv("LOGS_FOLDER")

    SERVICE_URL: str = os.getenv("SERVICE_URL")
    AS_URL: str = os.getenv("AS_URL")
    RS_URL: str = os.getenv("RS_URL")
    SCA_URL: str = os.getenv("SCA_URL")

    OAUTH2_CLIENT_ID: str = os.getenv("OAUTH2_CLIENT_ID")
    OAUTH2_CLIENT_SECRET: str = os.getenv("OAUTH2_CLIENT_SECRET")
    OAUTH2_CODE_CHALLENGE_METHOD: str = os.getenv("OAUTH2_CODE_CHALLENGE_METHOD")

    @property
    def oauth2_redirect_uri(self) -> str:
        return f"{self.SERVICE_URL}/oauth2/callback"

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

settings = Settings()
