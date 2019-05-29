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

FOUNDATION_EXPORT NSErrorDomain const OCSPTrustToLeafAndIssuerErrorDomain;

typedef NS_ERROR_ENUM(OCSPTrustToLeafAndIssuerErrorDomain, OCSPTrustToLeafAndIssuerErrorCode) {
    OCSPTrustToLeafAndIssuerErrorCodeUnknown = -1,
    OCSPTrustToLeafAndIssuerErrorCodeNoLeafCert,
    OCSPTrustToLeafAndIssuerErrorCodeNoIssuerCert
};

@interface OCSPTrustToLeafAndIssuer : NSObject

+ (void)leafAndIssuerFromSecTrustRef:(SecTrustRef)secTrustRef
                                leaf:(SecCertificateRef _Nonnull *_Nonnull)leaf
                              issuer:(SecCertificateRef _Nonnull *_Nonnull)issuer
                               error:(NSError**)error;

+ (SecCertificateRef)certAtIndex:(SecTrustRef)trust withIndex:(int)index;

@end

NS_ASSUME_NONNULL_END
