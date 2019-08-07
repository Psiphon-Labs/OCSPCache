/*
 * Copyright (c) 2019, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

@import XCTest;

#import <openssl/ocsp.h>
#import "OCSPAuthURLSessionDelegate.h"
#import "OCSPCache.h"
#import "OCSPCert.h"
#import "OCSPError.h"
#import "OCSPSecTrust.h"


@interface Tests : XCTestCase

@end

@implementation Tests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in
    // the class.
    [super tearDown];
}

/*
 * Tests for OCSP Cache implementation.
 *
 * NOTE: Certificates must be generated for testing Demo CA Certificates, see README.md
 * NOTE: OCSP Server must be running for `testDemoCACertificates` to pass, see README.md
 * NOTE: To clear the OCSP cache of the simulator use `Hardware->Erase All Content and Settings...`
 */

#pragma mark - Network request with authentication challenge

// Network request with an authentication challenge to exercise OCSPAuthURLSessionDelegate
- (void)testNetworkRequestWithAuthenticationChallenge {

    OCSPAuthURLSessionDelegate *authURLSessionDelegate =
    [self ocspAuthURLSessionDelegateWithLogging];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];

    NSURLSession *session =
    [NSURLSession sessionWithConfiguration:config
                                  delegate:authURLSessionDelegate
                             delegateQueue:NSOperationQueue.currentQueue];

    XCTestExpectation *expectResult =
    [self expectationWithDescription:@"Expected result from network request"];

    NSURLSessionDataTask *dataTask =
    [session dataTaskWithURL:[NSURL URLWithString:@"https://github.com/robots.txt"]
           completionHandler:^(NSData * _Nullable data,
                               NSURLResponse * _Nullable response,
                               NSError * _Nullable error) {

               XCTAssert(error == nil);
               XCTAssert(response != nil);

               [expectResult fulfill];
           }
     ];

    [dataTask resume];

    [self waitForExpectationsWithTimeout:60 handler:^(NSError * _Nullable error) {
        if (error != nil) {
            XCTFail(@"Timed out waiting for expectations: %@", error.localizedDescription);
        }
    }];
}

#pragma mark - Google Certificates

// Test OCSPCache with Google Certificate
- (void)testGoogleCertificates
{
    SecCertificateRef cert = [self googleLeafCert];

    SecCertificateRef issuer = [self googleIntermediateCert];

    [self ocspCacheTestWithCert:cert andIssuer:issuer];
}

#pragma mark - Cache lookup with trust

// Test OCSP Cache with trust object lookup
- (void)testCacheLookupWithTrust
{
    SecCertificateRef cert = [self localOCSPURLsCert];

    NSArray *certArray = @[(__bridge id)cert];

    SecPolicyRef policy;
    SecTrustRef trust;
    OSStatus status = SecTrustCreateWithCertificates((__bridge CFTypeRef)certArray,
                                                     policy,
                                                     &trust);
    if (status != 0) {
        XCTFail(@"Unexpected OSStatus %d. Check https://osstatus.com/.", status);
        return;
    }

    OCSPCache *ocspCache = [self ocspCacheWithLogging];

    XCTestExpectation *expectResult =
    [self expectationWithDescription:@"Expected result from cache"];

    [ocspCache lookup:trust
           andTimeout:10
        modifyOCSPURL:nil
              session:nil
           completion:^(OCSPCacheLookupResult * _Nonnull result) {
        [self checkResultAndEvaluate:trust
                                cert:cert
                              result:result
                               cache:ocspCache
                        expectCached:NO
                       expectSuccess:YES
                      evictOnFailure:NO];
        [expectResult fulfill];
    }];

    [self waitForExpectationsWithTimeout:60 handler:^(NSError * _Nullable error) {
        if (error != nil) {
            XCTFail(@"Timed out waiting for expectations: %@", error.localizedDescription);
        }
    }];
}

// Test OCSPAuthURLSessionDelegate retains trust policies
//
// Tests a previous bug where OCSPAuthURLSessionDelegate was
// overriding the policies set on the trust when setting the
// revocation policy.
- (void)testCacheLookupWithTrustHostnameMismatch
{
    SecCertificateRef cert = [self localOCSPURLsCert];

    NSArray *certArray = @[(__bridge id)cert];

    SecPolicyRef policy = SecPolicyCreateSSL(YES, (__bridge CFStringRef) @"google.com");

    SecTrustRef trust;
    OSStatus status = SecTrustCreateWithCertificates((__bridge CFTypeRef)certArray,
                                                     policy,
                                                     &trust);
    if (status != 0) {
        XCTFail(@"Unexpected OSStatus %d. Check https://osstatus.com/.", status);
        return;
    }

    OCSPAuthURLSessionDelegate *authURLSessionDelegate =
    [self ocspAuthURLSessionDelegateWithLogging];

    XCTestExpectation *expectResult =
    [self expectationWithDescription:@"Expected result from cache"];

    // TODO/NOTE: this evaluation fails multiple times because all the checks (OCSP, CRL, etc.)
    //            are done even though this is an irrecoverable failure. This is because the
    //            evaluation result is kSecTrustResultRecoverableTrustFailure and not
    //            kSecTrustSettingsResultDeny. In the future it would be worth seeing if we can
    //            inspect the error and determine if it is due to the SSLPolicy failing – then we
    //            could return kSecTrustSettingsResultDeny ourselves.
    [authURLSessionDelegate
        evaluateTrust:trust
        completionHandler:^(NSURLSessionAuthChallengeDisposition disposition,
                            NSURLCredential * _Nullable credential) {
            XCTAssert(credential == nil);
            XCTAssert(disposition == NSURLSessionAuthChallengeRejectProtectionSpace);

            OCSPSecTrustPrintPolicies(trust);
            XCTAssert(OCSPSecTrustSSLPolicyPresent(trust, @"google.com"));

            [expectResult fulfill];
        }
     ];

    [self waitForExpectationsWithTimeout:60 handler:^(NSError * _Nullable error) {
        if (error != nil) {
            XCTFail(@"Timed out waiting for expectations: %@", error.localizedDescription);
        }
    }];
}

#pragma mark - Demo CA

// Test OCSP Cache with Demo CA Certificate using local OCSP Server
- (void)testDemoCAWithGoodCertificate
{
    SecCertificateRef cert = [self localOCSPURLsCert];

    SecCertificateRef issuer = [self rootCACert];

    [self ocspCacheTestWithCert:cert andIssuer:issuer];
}

#pragma mark - Cache race

// Test OCSP Cache with Demo CA Certificate using local OCSP Server
// Do many lookups in parallel and ensure that all the results are
// cached except the initial request.
- (void)testDemoCAWithGoodCertificateCacheRace
{
    SecCertificateRef cert = [self localOCSPURLsCert];

    SecCertificateRef issuer = [self rootCACert];

    NSUInteger numTests = 1000;

    XCTestExpectation *expectResult =
    [self expectationWithDescription:@"Expected result from cache"];

    expectResult.expectedFulfillmentCount = numTests;

    OCSPCache *ocspCache = [self ocspCacheWithLogging];

    __block int numNotCached = 0;

    for (int i = 0; i < numTests; i++) {
        [ocspCache lookup:cert
               withIssuer:issuer
               andTimeout:10
            modifyOCSPURL:nil
                  session:nil
               completion:
         ^(OCSPCacheLookupResult *result) {
             XCTAssert(result != nil);
             XCTAssert(result.response != nil);
             XCTAssert(result.err == nil);
             if (!result.cached) {
                 @synchronized (self) {
                     numNotCached += 1;
                 }
             }
             [expectResult fulfill];
         }];
    }

    [self waitForExpectationsWithTimeout:60 handler:^(NSError * _Nullable error) {
        if (error != nil) {
            XCTFail(@"Timed out waiting for expectations: %@", error.localizedDescription);
        } else {
            XCTAssert(numNotCached == 1);
        }
    }];
}

#pragma mark - No OCSP URLs

// Certificate with no OCSP URLs should return an error
- (void)testDemoCAWithCertificateWithNoOCSPURLsCert
{
    NSTimeInterval defaultTimeout = 10;

    SecCertificateRef cert = [self noOCSPURLsCert];

    SecCertificateRef issuer = [self rootCACert];

    OCSPCache *ocspCache = [self ocspCacheWithLogging];

    // Expect the cache to return an error because there are no OCSP URLs in the certificate.

    XCTestExpectation *expectResult =
    [self expectationWithDescription:@"Expected error from cache"];

    [ocspCache lookup:cert
           withIssuer:issuer
           andTimeout:defaultTimeout
        modifyOCSPURL:nil
              session:nil
           completion:
     ^(OCSPCacheLookupResult *r) {
         XCTAssert(r.response == nil);
         XCTAssert(r.err != nil);
         XCTAssert(r.err.domain == OCSPCacheErrorDomain);
         XCTAssert(r.err.code == OCSPCacheErrorConstructingOCSPRequests);
         NSError *underlyingError = [r.err.userInfo objectForKey:NSUnderlyingErrorKey];
         XCTAssert(underlyingError != nil);
         XCTAssert(underlyingError.domain == OCSPCertErrorDomain);
         XCTAssert(underlyingError.code == OCSPCertErrorCodeNoOCSPURLs);
         XCTAssert(r.cached == FALSE);

         [expectResult fulfill];
     }];

    [self waitForExpectationsWithTimeout:defaultTimeout+1 handler:^(NSError * _Nullable error) {
        if (error != nil) {
            XCTFail(@"Timed out waiting for expectations: %@", error.localizedDescription);
        }
    }];
}

# pragma mark - Bad OCSP URLs

// Test OCSP Cache with Demo CA Certificate with bad OCSP URLs using local OCSP Server
- (void)testDemoCAWithCertificateWithBadOCSPURLsCert
{
    NSTimeInterval defaultTimeout = 5;

    SecCertificateRef cert = [self badOCSPURLsCert];

    SecCertificateRef issuer = [self rootCACert];

    OCSPCache *ocspCache = [self ocspCacheWithLogging];

    // Expect the cache to return an error because no response can be retrieved from the invalid
    // OCSP URLs

    XCTestExpectation *expectResult =
    [self expectationWithDescription:@"Expected error from cache"];

    [ocspCache lookup:cert
           withIssuer:issuer
           andTimeout:defaultTimeout
        modifyOCSPURL:nil
              session:nil
           completion:
     ^(OCSPCacheLookupResult *r) {
         XCTAssert(r.response == nil);
         XCTAssert(r.err != nil);
         XCTAssert(r.err.domain == OCSPCacheErrorDomain);
         XCTAssert(r.err.code == OCSPCacheErrorCodeNoSuccessfulResponse);
         XCTAssert(r.cached == FALSE);

         [expectResult fulfill];
     }];

    [self waitForExpectationsWithTimeout:60 handler:^(NSError * _Nullable error) {
        if (error != nil) {
            XCTFail(@"Timed out waiting for expectations: %@", error.localizedDescription);
        }
    }];
}

#pragma mark - Helpers for certificate evaluations

// Run a series of tests against the cache
- (void)ocspCacheTestWithCert:(SecCertificateRef)certRef andIssuer:(SecCertificateRef)issuerRef
{
    NSTimeInterval defaultTimeout = 10;

    NSArray *certArray = @[(__bridge id)certRef, (__bridge id)issuerRef];

    SecPolicyRef policy = SecPolicyCreateRevocation(kSecRevocationOCSPMethod |
                                                    kSecRevocationRequirePositiveResponse |
                                                    kSecRevocationNetworkAccessDisabled);

    SecTrustRef trust;
    OSStatus status = SecTrustCreateWithCertificates((__bridge CFTypeRef)certArray,
                                                     policy,
                                                     &trust);
    if (status != 0) {
        XCTFail(@"Unexpected OSStatus %d. Check https://osstatus.com/.", status);
        return;
    }

    OCSPCache *ocspCache = [self ocspCacheWithLogging];

    /// Cache miss

    [self cacheBasicTest:trust
                 certRef:certRef
                  issuer:issuerRef
                   cache:ocspCache
                 timeout:defaultTimeout
            expectCached:NO
           expectSuccess:YES
          evictOnFailure:NO];

    /// Cache hit

    [self cacheBasicTest:trust
                 certRef:certRef
                  issuer:issuerRef
                   cache:ocspCache
                 timeout:defaultTimeout
            expectCached:YES
           expectSuccess:YES
          evictOnFailure:NO];

    NSString *userDefaultsKey = @"OCSPCache.ocsp_cache1";
    NSUserDefaults *userDefaults = [NSUserDefaults standardUserDefaults];
    [ocspCache persistToUserDefaults:userDefaults withKey:userDefaultsKey];

    ocspCache =
    [[OCSPCache alloc] initWithLogger:^(NSString * _Nonnull logLine) {
        NSLog(@"[OCSPCache] %@", logLine);
    } andLoadFromUserDefaults:userDefaults withKey:userDefaultsKey];

    /// Cache hit after load from user defaults

    [self cacheBasicTest:trust
                 certRef:certRef
                  issuer:issuerRef
                   cache:ocspCache
                 timeout:defaultTimeout
            expectCached:YES
           expectSuccess:YES
          evictOnFailure:NO];

    /// Cache recovery from cached invalid data

    // Cache invalid data
    [ocspCache setCacheValueForCert:certRef data:[[NSData alloc] init]];

    [self cacheBasicTest:trust
                 certRef:certRef
                  issuer:issuerRef
                   cache:ocspCache
                 timeout:defaultTimeout
            expectCached:NO
           expectSuccess:YES
          evictOnFailure:NO];

    /// Cache recovery from cached invalid response

    // Create invalid response which indicates success
    OCSP_RESPONSE *r = OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, nil);
    unsigned char *ocspResponse = NULL;
    int len = i2d_OCSP_RESPONSE(r, &ocspResponse);
    NSData *d = [NSData dataWithBytes:ocspResponse length:len];

    // Cache valid data, but invalid response
    [ocspCache setCacheValueForCert:certRef data:d];

    // First attempt fails, but the invalid response is evicted
    [self cacheBasicTest:trust
                 certRef:certRef
                  issuer:issuerRef
                   cache:ocspCache
                 timeout:defaultTimeout
            expectCached:YES
           expectSuccess:NO
          evictOnFailure:YES];

    // Second attempt succeeds because there is invalid response in the cache
    [self cacheBasicTest:trust
                 certRef:certRef
                  issuer:issuerRef
                   cache:ocspCache
                 timeout:defaultTimeout
            expectCached:NO
           expectSuccess:YES
          evictOnFailure:NO];
}

// Helper for testing the cache
- (void)cacheBasicTest:(SecTrustRef)trust
               certRef:(SecCertificateRef)certRef
                issuer:(SecCertificateRef)issuerRef
                 cache:(OCSPCache*)cache
               timeout:(NSTimeInterval)timeout
          expectCached:(BOOL)expectCached
         expectSuccess:(BOOL)expectSuccess
        evictOnFailure:(BOOL)evictOnFailure
{
    XCTestExpectation *expectResult =
        [self expectationWithDescription:@"Expected result from cache"];

    [cache lookup:certRef
       withIssuer:issuerRef
       andTimeout:timeout
    modifyOCSPURL:nil
          session:nil
       completion:
     ^(OCSPCacheLookupResult * _Nonnull result) {

         [self checkResultAndEvaluate:trust
                                 cert:certRef
                               result:result
                                cache:cache
                         expectCached:expectCached
                        expectSuccess:expectSuccess
                       evictOnFailure:evictOnFailure];

         [expectResult fulfill];
     }];

    [self waitForExpectationsWithTimeout:timeout handler:^(NSError * _Nullable error) {
        if (error != nil) {
            XCTFail(@"Timed out waiting for expectations: %@", error.localizedDescription);
        }
    }];
}

// Helper for testing the cache
- (void)checkResultAndEvaluate:(SecTrustRef)trust
                          cert:(SecCertificateRef)cert
                        result:(OCSPCacheLookupResult*)result
                         cache:(OCSPCache*)cache
                  expectCached:(BOOL)expectCached
                 expectSuccess:(BOOL)expectSuccess
                evictOnFailure:(BOOL)evictOnFailure
{
     SecTrustResultType trustEvaluateResult = [self checkResultAndEvaulate:trust
                                                                    result:result
                                                              expectCached:expectCached];

     BOOL success =    trustEvaluateResult == kSecTrustResultProceed
                    || trustEvaluateResult == kSecTrustResultUnspecified;

     XCTAssert(success == expectSuccess);

     if (!success) {
         if (expectSuccess) {
             XCTFail(@"Unexpected result: %d", trustEvaluateResult);
         }
         if (evictOnFailure) {
             [cache removeCacheValueForCert:cert];
         }
     }
}

// Helper for checking cache results
- (SecTrustResultType)checkResultAndEvaulate:(SecTrustRef)trust
                                      result:(OCSPCacheLookupResult*)result
                                expectCached:(BOOL)expectCached {
    XCTAssert(result != nil);
    XCTAssert(result.err == nil);
    XCTAssert(result.response != nil);
    XCTAssert([result.response success] == TRUE);
    XCTAssert(result.cached == expectCached);

    CFDataRef ocspResponseDataRef = (__bridge CFDataRef)result.response.data;
    OSStatus status = SecTrustSetOCSPResponse(trust, ocspResponseDataRef);
    if (status != 0) {
        XCTFail(@"Unexpected OSStatus %d. Check https://osstatus.com/.", status);
    }

    // Check that there are no expired responses

    NSArray<RACThreeTuple<Error*,OCSPSingleResponse*,NSNumber*>*>* expiredResponses =
    [result.response expiredResponses];

    for (RACThreeTuple<Error*,OCSPSingleResponse*,NSNumber*>* expiredResponse
         in expiredResponses) {

        Error *err = [expiredResponse first];
        OCSPSingleResponse *r = [expiredResponse second];
        BOOL expired = [expiredResponse third].boolValue;
        XCTAssert(err == nil);
        XCTAssert(r != nil);
        XCTAssert(expired == FALSE);
    }

    SecTrustResultType trustEvaulateResult;
    status = SecTrustEvaluate(trust, &trustEvaulateResult);
    if (status != 0) {
        XCTFail(@"Unexpected OSStatus %d. Check https://osstatus.com/.", status);
    }

    return trustEvaulateResult;
}

#pragma mark - OCSPCache initialization

- (OCSPCache*)ocspCacheWithLogging {
    OCSPCache *cache=
    [[OCSPCache alloc] initWithLogger:^(NSString * _Nonnull logLine) {
        NSLog(@"[OCSPCache] %@", logLine);
    }];

    return cache;
}

#pragma mark - OCSPAuthURLSessionDelegate initialization

- (OCSPAuthURLSessionDelegate*)ocspAuthURLSessionDelegateWithLogging {
    void (^logger)(NSString * _Nonnull logLine) =
    ^(NSString * _Nonnull logLine) {
        NSLog(@"[OCSPAuthURLSessionDelegate] %@", logLine);
    };

    NSURL* (^modifyOCSPURL)(NSURL *url) =
    ^NSURL*(NSURL *url) {
        NSLog(@"[OCSPAuthURLSessionDelegate] Making OCSP request to %@", url);
        return nil;
    };

    OCSPCache *ocspCache = [self ocspCacheWithLogging];

    OCSPAuthURLSessionDelegate *authURLSessionDelegate =
    [[OCSPAuthURLSessionDelegate alloc] initWithLogger:logger
                                             ocspCache:ocspCache
                                         modifyOCSPURL:modifyOCSPURL
                                               session:nil];

    return authURLSessionDelegate;
}

#pragma mark - Certificate loading

/// Google Certificates

- (SecCertificateRef)googleLeafCert {
    return [self loadCertificateFailOnError:@"Certs/Google/cert.der"
                         expectedCommonName:@"www.google.com"];
}

- (SecCertificateRef)googleIntermediateCert {
    return [self loadCertificateFailOnError:@"Certs/Google/intermediate.der"
                         expectedCommonName:@"Google Internet Authority G3"];
}

- (SecCertificateRef)googleRootCert {
    return [self loadCertificateFailOnError:@"Certs/Google/root.der"
                         expectedCommonName:@"www.google.com"];
}

/// Local Certificates

- (SecCertificateRef)localOCSPURLsCert {
    return [self loadCertificateFailOnError:@"Certs/DemoCA/local_ocsp_urls.der"
                         expectedCommonName:@"Local OCSP URLs"];
}

- (SecCertificateRef)badOCSPURLsCert {
    return [self loadCertificateFailOnError:@"Certs/DemoCA/bad_ocsp_urls.der"
                         expectedCommonName:@"Bad OCSP URLs"];
}

- (SecCertificateRef)noOCSPURLsCert {
    return [self loadCertificateFailOnError:@"Certs/DemoCA/no_ocsp_urls.der"
                         expectedCommonName:@"No OCSP URLs"];
}

- (SecCertificateRef)rootCACert {
    return [self loadCertificateFailOnError:@"Certs/DemoCA/root_CA.der"
                         expectedCommonName:@"Demo CA"];
}

#pragma mark - Helpers for loading certificates

- (SecCertificateRef)loadCertificateFailOnError:(NSString*)filePath
                             expectedCommonName:(NSString*)expectedCommonName {
    SecCertificateRef cert;

    Error *e = [self loadCertificate:filePath
                  expectedCommonName:expectedCommonName
                             certRef:&cert];
    if (e) {
        XCTFail(@"%@", e);
    }

    return cert;
}

// Load certificate and check that common name matches
- (Error*)loadCertificate:(NSString*)filePath
       expectedCommonName:(NSString*)expectedCommonName
                  certRef:(SecCertificateRef*)certRef {
    *certRef = NULL;
    Error *e = [self loadCertificate:filePath secCertRef:certRef];
    if (e != nil) {
        return [NSString stringWithFormat:@"%@", e];
    }

    CFStringRef stringRef = NULL;
    OSStatus status = SecCertificateCopyCommonName(*certRef, &stringRef);
    if (status != 0) {
        return [NSString stringWithFormat:@"Unexpected OSStatus %d. Check https://osstatus.com/.",
                status];
    }

    NSString *commonName = CFBridgingRelease(stringRef);

    if (![commonName isEqualToString:expectedCommonName]) {
        return [NSString stringWithFormat:@"Unexpected Common Name: %@, expected: %@",
                commonName,
                expectedCommonName];
    }

    return nil;
}

// Load certificate in DER format
- (Error*)loadCertificate:(NSString*)fileName
               secCertRef:(SecCertificateRef*)secCertRef {
    *secCertRef = NULL;

    NSBundle *bundle = [NSBundle bundleForClass:self.class];
    NSString *path = [bundle pathForResource:fileName ofType:nil];
    NSFileManager *fileManager = [NSFileManager defaultManager];

    if ([fileManager fileExistsAtPath:path] == FALSE) {
        return  [NSString stringWithFormat:
                 @"Certificate \"%@\" does not exist at path \"%@\"",
                 fileName,
                 bundle.bundlePath];
    }

    NSData *certData = [fileManager contentsAtPath:path];

    *secCertRef = SecCertificateCreateWithData(nil, (__bridge CFDataRef)certData);

    return nil;
}

@end
