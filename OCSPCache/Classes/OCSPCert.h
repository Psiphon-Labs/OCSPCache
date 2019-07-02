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

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const OCSPCertErrorDomain;

typedef NS_ERROR_ENUM(OCSPCertErrorDomain, OCSPCertErrorCode) {
    OCSPCertErrorCodeUnknown = -1,
    OCSPCertErrorCodeInvalidTrustObject = 1,
    OCSPCertErrorCodeSecCertToX509Failed,
    OCSPCertErrorCodeNoOCSPURLs,
    OCSPCertErrorCodeEVPAllocFailed,
    OCSPCertErrorCodeCertToIdFailed,
    OCSPCertErrorCodeReqAllocFailed,
    OCSPCertErrorCodeAddCertsToReqFailed,
    OCSPCertErrorCodeFailedToSerializeOCSPReq,
    OCSPCertErrorCodeConstructedInvalidURL
};

/// Access OCSP data within certificates
@interface OCSPCert : NSObject

/// Return OCSP URLs contained within the provided certificate.
///
/// Check in SecTrustRef (X.509 cert) for Online Certificate Status Protocol (1.3.6.1.5.5.7.48.1) authority information access method.
/// This is found in the Certificate Authority Information Access (1.3.6.1.5.5.7.1.1) X.509v3 extension. Return a URL for each OCSP
/// access method found within the certificate.
/// @param secCertRef  Target certificate.
/// @param error Any error encountered while attempting to access OCSP URLs. If set, the return value should be ignored.
+ (NSArray<NSURL*>*_Nullable)ocspURLsFromSecCertRef:(SecCertificateRef)secCertRef
                                              error:(NSError**)error;

/// Return OCSP URLs contained within the provided certificate.
///
/// Check in SecTrustRef (X.509 cert) for Online Certificate Status Protocol (1.3.6.1.5.5.7.48.1) authority information access method.
/// This is found in the Certificate Authority Information Access (1.3.6.1.5.5.7.1.1) X.509v3 extension. Return a URL for each OCSP
/// access method found within the certificate.
/// @param secTrustRef  Target trust reference.
/// @param error Any error encountered while attempting to access OCSP URLs. If set, the return value should be ignored.
+ (NSArray<NSURL*>*_Nullable)ocspURLsFromSecTrustRef:(SecTrustRef)secTrustRef
                                               error:(NSError**)error;

/// Return data required for an OCSP request using the POST method.
///
/// From https://tools.ietf.org/html/rfc6960#appendix-A.1
/// > An OCSP request using the POST method is constructed as follows: The
/// > Content-Type header has the value "application/ocsp-request", while
/// > the body of the message is the binary value of the DER encoding of
/// > the OCSPRequest.
///
/// @param secTrustRef  Target trust reference. Must include the target certificate and the certificate
/// of its issuer.
/// @param error Any error encountered whne trying to construct the OCSP request data. If set, the return value should be ignored.
+ (NSData*)ocspDataForPostRequestFromSecTrustRef:(SecTrustRef)secTrustRef
                                           error:(NSError**)error;

/// Return data required for an OCSP request using the POST method.
///
/// From https://tools.ietf.org/html/rfc6960#appendix-A.1
/// > An OCSP request using the POST method is constructed as follows: The
/// > Content-Type header has the value "application/ocsp-request", while
/// > the body of the message is the binary value of the DER encoding of
/// > the OCSPRequest.
///
/// @param secCertRef Target certificate.
/// @param issuerCertRef  Issuer certificate of the target certificate.
/// @param error Any error encountered whne trying to construct the OCSP request data. If set, the return value should be ignored.
+ (NSData*)ocspDataForPostRequestFromSecCertRef:(SecCertificateRef)secCertRef
                              withIssuerCertRef:(SecCertificateRef)issuerCertRef
                                          error:(NSError**)error;

@end

NS_ASSUME_NONNULL_END
