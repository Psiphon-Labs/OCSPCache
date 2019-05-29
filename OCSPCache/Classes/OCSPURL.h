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

FOUNDATION_EXPORT NSErrorDomain const OCSPErrorDomain;

typedef NS_ERROR_ENUM(OCSPErrorDomain, OCSPErrorCode) {
    OCSPErrorCodeUnknown = -1,
    OCSPErrorCodeInvalidTrustObject = 1,
    OCSPErrorCodeSecCertToX509Failed,
    OCSPErrorCodeNoOCSPURLs,
    OCSPErrorCodeEVPAllocFailed,
    OCSPErrorCodeCertToIdFailed,
    OCSPErrorCodeReqAllocFailed,
    OCSPErrorCodeAddCertsToReqFailed,
    OCSPErrorCodeFailedToSerializeOCSPReq,
    OCSPErrorCodeConstructedInvalidURL
};

/*
 * Check in SecTrustRef (X.509 cert) for Online Certificate Status Protocol (1.3.6.1.5.5.7.48.1)
 * authority information access method. This is found in the
 * Certificate Authority Information Access (1.3.6.1.5.5.7.1.1) X.509v3 extension.
 *
 * A OCSP request is constructed for each OCSP URL within the certificate. An OCSP request using the
 * GET method is constructed as follows:
 * {url}/{url-encoding of base-64 encoding of the DER encoding of the OCSPRequest}
 *
 * OCSP GET request format: https://tools.ietf.org/html/rfc2560#appendix-A.1.1
 * X.509 Authority Information Access: https://tools.ietf.org/html/rfc2459#section-4.2.2.1
 */
@interface OCSPURL : NSObject

+ (NSArray<NSURL*>*_Nullable)ocspURLsFromSecCertRef:(SecCertificateRef)secCertRef
                                  withIssuerCertRef:(SecCertificateRef)issuerCertRef
                                              error:(NSError**)error;

+ (NSArray<NSURL*>*_Nullable)ocspURLsFromSecTrustRef:(SecTrustRef)secTrustRef
                                               error:(NSError**)error;

@end

NS_ASSUME_NONNULL_END
