# Changelog

## [0.1.1]

_30 Jan 2025_

### Updated:

- Improve error logs and refactoring.

## [0.1.0]

_13 Jan 2025_

### Added:

- Initial release of the Relying Party Web Service.
- Support for form-based login
- REST API client integration for QTSP and SCA:
  - QTSP OAuth2 requests
  - QTSP Credentials list request
  - SCA signature request
- Core HTML pages:
  - '/tester/login' for form-based login
  - '/tester/select_document' for selecting a document
  - '/tester/service_authorization' to initiate OAuth2 Authorization with the 'service' scope
  - '/tester/credentials_list' to display a list of available certificates
  - '/tester/signed_document_download' to download the signed document
- Example document provided for testing signatures
