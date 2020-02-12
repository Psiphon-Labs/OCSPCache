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

#import "OCSPSecTrust.h"


// See comment in header
NSArray* OCSPSecTrustProperties(SecTrustRef trust) {
    return (__bridge_transfer NSArray*)SecTrustCopyProperties(trust);
}

// See comment in header
void OCSPSecTrustPrintProperties(SecTrustRef trust) {
    NSArray *properties = OCSPSecTrustProperties(trust);
    for (int i = 0; i < [properties count]; i++) {
        NSLog(@"Trust property [%d]: %@", i, [properties objectAtIndex:i]);
    }
}

// See comment in header
void OCSPSecTrustAddPolicy(SecTrustRef trust, SecPolicyRef policy) {
    CFArrayRef policies;
    SecTrustCopyPolicies(trust, &policies);

    NSArray *newPolicies = (__bridge_transfer NSArray*)policies;
    newPolicies = [newPolicies arrayByAddingObject:(__bridge_transfer id)policy];
    SecTrustSetPolicies(trust, (__bridge CFArrayRef)newPolicies);
}

// See comment in header
void OCSPSecTrustPrintPolicies(SecTrustRef trust) {
    CFArrayRef policies = (__bridge CFArrayRef)OCSPSecTrustPolicies(trust);
    CFIndex policyCount = CFArrayGetCount(policies);

    for (int i = 0; i < policyCount; i++) {
        NSDictionary *p = OCSPSecTrustPoliciesAtIndex(trust, i);
        NSLog(@"Trust policy [%d]: %@", i, p);
    }
}

// See comment in header
NSArray* OCSPSecTrustPolicies(SecTrustRef trust) {
    CFArrayRef policies;
    SecTrustCopyPolicies(trust, &policies);

    return (__bridge_transfer NSArray*)policies;
}

// See comment in header
NSDictionary* OCSPSecTrustPoliciesAtIndex(SecTrustRef trust, int index) {
    CFArrayRef policies = (__bridge CFArrayRef)OCSPSecTrustPolicies(trust);

    SecPolicyRef policy = (SecPolicyRef)CFArrayGetValueAtIndex(policies, index);
    CFDictionaryRef properties = SecPolicyCopyProperties(policy);

    return (__bridge_transfer NSDictionary*)properties;
}

// See comment in header
bool OCSPSecTrustSSLPolicyPresent(SecTrustRef trust, NSString *hostname) {
    NSDictionary *expectedPolicy =
        @{
          (__bridge_transfer NSString*)kSecPolicyName: hostname,
          (__bridge_transfer NSString*)kSecPolicyOid: (__bridge_transfer NSString*)kSecPolicyAppleSSL
          };

    return OCSPSecTrustPolicyPresent(trust, expectedPolicy);
}

// See comment in header
bool OCSPSecTrustPolicyPresent(SecTrustRef trust, NSDictionary *expectedPolicy) {
    CFArrayRef policies = (__bridge CFArrayRef)OCSPSecTrustPolicies(trust);
    CFIndex policyCount = CFArrayGetCount(policies);

    for (int i = 0; i < policyCount; i++) {
        NSDictionary *policy = OCSPSecTrustPoliciesAtIndex(trust, i);

        if (policy == nil) {
            continue;
        } else {
            return [policy isEqual:expectedPolicy];
        }
    }

    return FALSE;
}
