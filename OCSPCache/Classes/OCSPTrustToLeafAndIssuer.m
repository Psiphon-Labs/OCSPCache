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

#import "OCSPTrustToLeafAndIssuer.h"

NSErrorDomain _Nonnull const OCSPTrustToLeafAndIssuerErrorDomain =
                           @"OCSPTrustToLeafAndIssuerErrorDomain";

@implementation OCSPTrustToLeafAndIssuer

+ (void)leafAndIssuerFromSecTrustRef:(SecTrustRef)secTrustRef
                                leaf:(SecCertificateRef*)leaf
                              issuer:(SecCertificateRef*)issuer
                               error:(NSError**)error {

    *error = nil;

    *leaf = [OCSPTrustToLeafAndIssuer certAtIndex:secTrustRef withIndex:0];
    if (*leaf == NULL) {
        *error = [NSError errorWithDomain:OCSPTrustToLeafAndIssuerErrorDomain
                                     code:OCSPTrustToLeafAndIssuerErrorCodeNoLeafCert
                                 userInfo:@{NSLocalizedDescriptionKey:@"Failed to get leaf "
                                                                       "certificate"}];
        return;
    }

    *issuer = [OCSPTrustToLeafAndIssuer certAtIndex:secTrustRef withIndex:1];
    if (*issuer == NULL) {
        *error = [NSError errorWithDomain:OCSPTrustToLeafAndIssuerErrorDomain
                                     code:OCSPTrustToLeafAndIssuerErrorCodeNoIssuerCert
                                 userInfo:@{NSLocalizedDescriptionKey:@"Failed to get issuer "
                                            "certificate"}];
        return;
    }
}

+ (SecCertificateRef)certAtIndex:(SecTrustRef)trust withIndex:(int)index {
    if (SecTrustGetCertificateCount(trust) < index) {
        return nil;
    }

    SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust, index);

    return cert;
}

@end
