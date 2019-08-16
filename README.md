# OCSPCache

OCSPCache is used for making OCSP requests and caching OCSP responses.

## Testing

### Prerequisites

#### Install OpenSSL 1.0.2r
https://github.com/openssl/openssl/releases/tag/OpenSSL_1_0_2r

#### Install CocoaPods
https://cocoapods.org/

### Setup

#### Generate Certificates for testing
Run [setup.sh](./Example/Tests/Certs/DemoCA/setup.sh) in [./Example/Tests/Certs/DemoCA/](./Example/Tests/Certs/DemoCA/)

#### Install the root certificate on the simulator
- Open Finder and drag `./Example/Tests/Certs/DemoCA/CA/root/root_CA.crt` onto the simulator window
- Click allow
- Navigate in the simulator to `Settings->Profiles` and click on the downloaded profile
- Click install
- Navigate in the simulator to `Settings->About->Certificate Trust Settings`
- Enable the switch "Enable Full Trust For Root Certificates" for the installed certificate

#### Start the OCSP Servers
Run the root OCSP Server [run_root_ocsp_server.sh](./Example/Tests/Certs/DemoCA/run_root_ocsp_server.sh).

Run the intermediate OCSP Server [run_intermediate_ocsp_server.sh](./Example/Tests/Certs/DemoCA/run_intermediate_ocsp_server.sh).

#### Setup Project
- Run `pod install` in [./Example](./Example)
- Open `OCSPCache.xcworkspace` with Xcode

### Run Tests

Test using the simulator or ensure that the device being used for testing has access to the OCSP server running locally.

---


### Revoking Certificates

Revoke the certificate with local OCSP URLs: [revoke_local_ocsp_urls_cert.sh](./Example/Tests/Certs/DemoCA/revoke_local_ocsp_urls_cert.sh).

Revoke the intermediate certificate: [revoke_intermediate_CA_cert.sh](./Example/Tests/Certs/DemoCA/revoke_intermediate_CA_cert.sh).
