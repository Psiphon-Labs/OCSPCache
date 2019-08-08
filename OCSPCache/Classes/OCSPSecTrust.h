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


/// Methods for working with SecTrustRef

/**
 Print properties on trust corresponding to last trust evaluation.

 @param trust Trust.
 @return Return properties on trust.
 @discussion See documentation for 'SecTrustCopyProperties'.
 */
NSArray* OCSPSecTrustProperties(SecTrustRef trust);
/**
 Print properties on trust corresponding to last trust evaluation.

 @param trust Trust.
 */
void OCSPSecTrustPrintProperties(SecTrustRef trust);

/**
 Append policy to existing policies set on trust.

 @param trust Trust.
 @param policy Policy to add.
 */
void OCSPSecTrustAddPolicy(SecTrustRef trust, SecPolicyRef policy);

/**
 Print policies set on trust.

 @param trust Trust.
 */
void OCSPSecTrustPrintPolicies(SecTrustRef trust);

/**
 Return policies set on trust. Transfers ownership of CF references to ARC.

 @param trust Trust.
 @return Policies set on trust.
 */
NSArray* OCSPSecTrustPolicies(SecTrustRef trust);

/**
 Returns policy at specified index. Transfers ownership of CF references to ARC.

 @param trust Trust.
 @return Policy at specified index.
 */
NSDictionary* OCSPSecTrustPoliciesAtIndex(SecTrustRef trust, int index);

/**
 Check if SSL policy is set on trust.

 @param trust Trust.
 @param hostname Expected hostname.
 @return Returns true if SSL policy matches.
 */
bool OCSPSecTrustSSLPolicyPresent(SecTrustRef trust, NSString *hostname);

/**
 Check if trust has been configured with the specified policy.

 @param trust Trust.
 @param expectedPolicy Expected policy.
 @return Returns true if a policy is found which matches the expected policy.
 */
bool OCSPSecTrustPolicyPresent(SecTrustRef trust, NSDictionary *expectedPolicy);
