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

#import "OCSPURL.h"
#import <openssl/ocsp.h>
#import <openssl/safestack.h>
#import <openssl/x509.h>
#import <openssl/x509v3.h>
#import "OCSPOpenSSLBridge.h"
#import "OCSPTrustToLeafAndIssuer.h"
#import "OCSPURLEncode.h"

NSErrorDomain _Nonnull const OCSPErrorDomain = @"OCSPErrorDomain";

@implementation OCSPURL

+ (NSArray<NSURL*>*_Nullable)ocspURLsFromSecTrustRef:(SecTrustRef)secTrustRef
                                               error:(NSError**)error {

    NSError *e;
    SecCertificateRef leaf;
    SecCertificateRef issuer;

    [OCSPTrustToLeafAndIssuer leafAndIssuerFromSecTrustRef:secTrustRef
                                                      leaf:&leaf
                                                    issuer:&issuer
                                                     error:&e];

    if (e) {
        *error = [NSError errorWithDomain:OCSPErrorDomain
                                     code:OCSPErrorCodeInvalidTrustObject
                                 userInfo:@{NSLocalizedDescriptionKey:@"Invalid trust object",
                                            NSUnderlyingErrorKey:e}];
        return nil;
    }

    NSArray<NSURL*>* urls = [OCSPURL ocspURLsFromSecCertRef:leaf withIssuerCertRef:issuer error:error];

    return urls;
}

+ (NSArray<NSURL*>*_Nullable)ocspURLsFromSecCertRef:(SecCertificateRef)secCertRef
                                  withIssuerCertRef:(SecCertificateRef)issuerCertRef
                                              error:(NSError**)error {
    
    NSMutableArray <void(^)(void)> *cleanup = [[NSMutableArray alloc] init];
    
    X509 *leaf = [OCSPOpenSSLBridge secCertRefToX509:secCertRef];
    if (leaf == NULL) {
        *error = [NSError errorWithDomain:OCSPErrorDomain
                                     code:OCSPErrorCodeSecCertToX509Failed
                                 userInfo:@{NSLocalizedDescriptionKey:@"Failed to convert leaf "
                                                                       "cert to OpenSSL X509 "
                                                                       "object"}];
        return nil;
    }
    
    [cleanup addObject:^(){
        X509_free(leaf);
    }];
    
    X509 *issuer = [OCSPOpenSSLBridge secCertRefToX509:issuerCertRef];
    if (issuer == NULL) {
        *error = [NSError errorWithDomain:OCSPErrorDomain
                                     code:OCSPErrorCodeSecCertToX509Failed
                                 userInfo:@{NSLocalizedDescriptionKey:@"Failed to convert issuer "
                                                                       "cert to OpenSSL X509 "
                                                                       "object"}];
    }
    
    [cleanup addObject:^(){
        X509_free(issuer);
    }];
    
    NSArray<NSString*>* ocspURLs = [OCSPURL OCSPURLs:leaf];
    if ([ocspURLs count] == 0) {
        *error = [NSError errorWithDomain:OCSPErrorDomain
                                     code:OCSPErrorCodeNoOCSPURLs
                                 userInfo:@{NSLocalizedDescriptionKey:@"Found 0 OCSP URLs in "
                                                                       "leaf certificate"}];
        [OCSPURL execCleanupTasks:cleanup];
        return nil;
    }
    
    const EVP_MD *cert_id_md = EVP_sha1();
    if (cert_id_md == NULL) {
        *error = [NSError errorWithDomain:OCSPErrorDomain
                                     code:OCSPErrorCodeEVPAllocFailed
                                 userInfo:@{NSLocalizedDescriptionKey:@"Failed to allocate new EVP "
                                                                       "sha1"}];
        [OCSPURL execCleanupTasks:cleanup];
        return nil;
    }
    
    OCSP_CERTID *id_t = OCSP_cert_to_id(cert_id_md, leaf, issuer);
    if (id_t == NULL) {
        *error = [NSError errorWithDomain:OCSPErrorDomain
                                     code:OCSPErrorCodeCertToIdFailed
                                 userInfo:@{NSLocalizedDescriptionKey:@"Failed to create "
                                                                       "OCSP_CERTID structure"}];
        [OCSPURL execCleanupTasks:cleanup];
        return nil;
    }
    
    // Construct OCSPURL request
    //
    // https://www.ietf.org/rfc/rfc2560.txt
    //
    // An OCSPURL request using the GET method is constructed as follows:
    //
    // GET {url}/{url-encoding of base-64 encoding of the DER encoding of
    //	   the OCSPRequest}
    
    OCSP_REQUEST *req = OCSP_REQUEST_new();
    if (req == NULL) {
        *error = [NSError errorWithDomain:OCSPErrorDomain
                                     code:OCSPErrorCodeReqAllocFailed
                                 userInfo:@{NSLocalizedDescriptionKey:@"Failed to allocate new "
                                                                       "OCSP request"}];
        [OCSPURL execCleanupTasks:cleanup];
        return nil;
    }
    
    [cleanup addObject:^(){
        OCSP_REQUEST_free(req);
    }];
    
    if (OCSP_request_add0_id(req, id_t) == NULL) {
        *error = [NSError errorWithDomain:OCSPErrorDomain
                                     code:OCSPErrorCodeAddCertsToReqFailed
                                 userInfo:@{NSLocalizedDescriptionKey:@"Failed to add certs to "
                                                                       "OCSP request"}];
        [OCSPURL execCleanupTasks:cleanup];
        return nil;
    }
    
    unsigned char *ocspReq = NULL;
    
    int len = i2d_OCSP_REQUEST(req, &ocspReq);
    
    if (ocspReq == NULL) {
        *error = [NSError errorWithDomain:OCSPErrorDomain
                                     code:OCSPErrorCodeFailedToSerializeOCSPReq
                                 userInfo:@{NSLocalizedDescriptionKey:@"Failed to serialize "
                                                                       "OCSP request"}];
        [OCSPURL execCleanupTasks:cleanup];
        return nil;
    }
    
    [cleanup addObject:^(){
        free(ocspReq);
    }];
    
    NSData *ocspReqData = [NSData dataWithBytes:ocspReq length:len];
    NSString *encodedOCSPReqData = [ocspReqData base64EncodedStringWithOptions:kNilOptions];
    NSString *escapedAndEncodedOCSPReqData = [URLEncode encode:encodedOCSPReqData];
    
    NSMutableArray<NSURL*>* reqURLs = [[NSMutableArray alloc] initWithCapacity:[ocspURLs count]];
    
    for (NSString *ocspURL in ocspURLs) {
        
        NSString *reqURL = [NSString stringWithFormat:@"%@/%@",
                                                      ocspURL,
                                                      escapedAndEncodedOCSPReqData];
        
        NSURL *url = [NSURL URLWithString:reqURL];
        if (url == nil) {
            NSString *localizedDescription = [NSString stringWithFormat:@"Constructed invalid URL "
                                                                         "for OCSP request: %@",
                                                                        reqURL];
            *error = [NSError errorWithDomain:OCSPErrorDomain
                                         code:OCSPErrorCodeConstructedInvalidURL
                                     userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];
            [OCSPURL execCleanupTasks:cleanup];
            return nil;
        }
        
        [reqURLs addObject:url];
    }
    
    [OCSPURL execCleanupTasks:cleanup];
    
    return reqURLs;
}

#pragma mark - Internal Helpers

+ (NSArray<NSString*>*)OCSPURLs:(X509*)x {
    STACK_OF(OPENSSL_STRING) *ocspURLs = X509_get1_ocsp(x);

    NSMutableArray *URLs = [[NSMutableArray alloc] init];

    for (int i = 0; i < sk_OPENSSL_STRING_num(ocspURLs); i++) {
        [URLs addObject:[NSString stringWithCString:sk_OPENSSL_STRING_value(ocspURLs, i)
                                           encoding:NSUTF8StringEncoding]];
    }
    
    sk_OPENSSL_STRING_free(ocspURLs);
    
    return URLs;
}

+ (void)execCleanupTasks:(NSArray<void(^)(void)> *)cleanupTasks {
    for (void (^cleanupTask)(void) in cleanupTasks) {
        cleanupTask();
    }
}

@end
