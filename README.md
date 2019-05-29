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
- Open Finder and drag `./Example/Tests/Certs/DemoCA/root_CA.crt` onto the simulator window
- Click allow
- Navigate in the simulator to `Settings->Profiles` and click on the downloaded profile
- Click install

#### Start the OCSP Server
Run the OCSP Server [run_ocsp_server](./Example/Tests/Certs/DemoCA/run_ocsp_server.sh) in [./Example/Tests/Certs/DemoCA/](./Example/Tests/Certs/DemoCA/)

#### Setup Project
- Run `pod install` in [./Example](./Example)
- Open `OCSPCache.xcworkspace` with Xcode

### Run Tests

Test using the simulator or ensure that the device being used for testing has access to the OCSP server running locally.
