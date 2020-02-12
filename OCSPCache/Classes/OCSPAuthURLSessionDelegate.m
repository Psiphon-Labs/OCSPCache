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

#import "OCSPAuthURLSessionDelegate.h"

#import "OCSPCache.h"
#import "OCSPURLEncode.h"
#import "OCSPSecTrust.h"

@implementation OCSPAuthURLSessionDelegate {
    void (^logger)(NSString*);
    NSURL* (^modifyOCSPURL)(NSURL *url);
    OCSPCache* ocspCache;
    NSURLSession *session;
    NSTimeInterval timeout;
    void (^successfullyValidatedTrust)(SecTrustRef trust);
}

- (instancetype)init {
    self = [super init];

    if (self) {
        self->ocspCache =
        [[OCSPCache alloc] initWithLogger:^(NSString * _Nonnull logLine) {
            NSLog(@"[OCSPCache] %@", logLine);
        }];
        self->timeout = 0;
    }

    return self;
}

/// See comment in header
-  (instancetype)initWithLogger:(void (^)(NSString*))logger
                      ocspCache:(nonnull OCSPCache *)ocspCache
                  modifyOCSPURL:(nullable NSURL * _Nonnull (^)(NSURL * _Nonnull))modifyOCSPURL
                        session:(NSURLSession * _Nullable)session
                        timeout:(NSTimeInterval)timeout {
    self = [super init];

    if (self) {
        self->logger = logger;
        self->ocspCache = ocspCache;
        self->modifyOCSPURL = modifyOCSPURL;
        if (session) {
            self->session = session;
        } else {
            NSURLSessionConfiguration *config =
            [NSURLSessionConfiguration ephemeralSessionConfiguration];

            self->session = [NSURLSession sessionWithConfiguration:config];
        }
        assert(timeout >= 0);
        self->timeout = timeout;
    }

    return self;
}

#pragma mark - NSURLSessionDelegate implementation

// See comment in header
-    (void)URLSession:(NSURLSession *)session
  didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler {
#pragma unused(session)
    assert(challenge != nil);
    assert(completionHandler != nil);

    // Resolve NSURLAuthenticationMethodServerTrust ourselves
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {

        [self logWithFormat:@"Got SSL certificate for %@", challenge.protectionSpace.host];

        SecTrustRef trust = challenge.protectionSpace.serverTrust;

        [self evaluateTrust:trust completionHandler:completionHandler];

        return;
    }

    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

#pragma mark - NSURLSessionTaskDelegate implementation

/// See comment in header
- (void) URLSession:(NSURLSession *)session
               task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
  completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler
{
#pragma unused(session)
    assert(challenge != nil);
    assert(completionHandler != nil);

    // Resolve NSURLAuthenticationMethodServerTrust ourselves
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        [self logWithFormat:@"Got SSL certificate for %@, mainDocumentURL: %@, URL: %@",
         challenge.protectionSpace.host,
         [task.currentRequest mainDocumentURL],
         [task.currentRequest URL]];

        SecTrustRef trust = challenge.protectionSpace.serverTrust;

        [self evaluateTrust:trust completionHandler:completionHandler];

        return;
    }

    completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

#pragma mark - Certificate validation

/// See comment in header
- (BOOL)evaluateTrust:(SecTrustRef)trust
    completionHandler:(AuthCompletion)completionHandler {

    return [self evaluateTrust:trust
         modifyOCSPURLOverride:nil
               sessionOverride:nil
             completionHandler:completionHandler];
}

/// See comment in header
- (BOOL)evaluateTrust:(SecTrustRef)trust
modifyOCSPURLOverride:(nullable NSURL * _Nonnull (^)(NSURL * _Nonnull))modifyOCSPURLOverride
      sessionOverride:(NSURLSession*)sessionOverride
    completionHandler:(AuthCompletion)completionHandler {

    NSURL* (^modifyOCSPURL)(NSURL *url);

    if (modifyOCSPURLOverride) {
        modifyOCSPURL = modifyOCSPURLOverride;
    } else {
        modifyOCSPURL = self->modifyOCSPURL;
    }

    NSURLSession *session;
    if (sessionOverride) {
        session = sessionOverride;
    } else {
        session = self->session;
    }

    BOOL completed;
    BOOL completedWithError;

    // Copy the original set of policies so the original set can be
    // restored after each evaluation attempt.
    CFArrayRef originalPolicies;
    SecTrustCopyPolicies(trust, &originalPolicies);

    // Check if there is a pinned or cached OCSP response

    [self trySystemOCSPNoRemote:trust
               originalPolicies:originalPolicies
                      completed:&completed
             completedWithError:&completedWithError
              completionHandler:completionHandler];

    if (completed) {
        SecTrustSetPolicies(trust, originalPolicies);
        [self logWithFormat:@"Pinned or cached OCSP response found by the system"];
        return TRUE;
    }

    // No pinned OCSP response, try fetching one

    [self logWithFormat:@"Fetching OCSP response through OCSPCache"];

    NSArray<OCSPCacheLookupResult*> *results = [self->ocspCache lookupAll:trust
                                                               andTimeout:self->timeout
                                                            modifyOCSPURL:modifyOCSPURL
                                                                  session:session];

    BOOL evictedResponse;

    [self evaluateOCSPCacheResult:results
                 originalPolicies:originalPolicies
                  evictedResponse:&evictedResponse
                            trust:trust
                        completed:&completed
               completedWithError:&completedWithError
                completionHandler:completionHandler];

    if (completed) {
        SecTrustSetPolicies(trust, originalPolicies);
        [self logWithFormat:@"Completed with OCSP response"];
        return TRUE;
    }

    // Check if check failed and a response was evicted from the cache
    if (!completed && evictedResponse) {
        // In the scenario that an intermediate certificate in the chain was missing,
        // but retrievable through an X509 extension:
        // - The first SecTrustEvaluate will fail, but the missing certificates will be downloaded
        //   in this step
        // - The responses will be evicted
        // We should retry in this scenario because missing certificates may have been fetched.

        // Cache returned pending response
        NSArray<OCSPCacheLookupResult*> *results = [self->ocspCache lookupAll:trust
                                                                   andTimeout:self->timeout
                                                                modifyOCSPURL:modifyOCSPURL
                                                                      session:session];

        [self evaluateOCSPCacheResult:results
                     originalPolicies:originalPolicies
                      evictedResponse:&evictedResponse
                                trust:trust
                            completed:&completed
                   completedWithError:&completedWithError
                    completionHandler:completionHandler];
        if (completed) {
            SecTrustSetPolicies(trust, originalPolicies);
            [self logWithFormat:@"Completed with OCSP response after evict and fetch"];
            return TRUE;
        }
    }

    // Try system CRL check and require a positive response

    [self trySystemCRL:trust
      originalPolicies:originalPolicies
             completed:&completed
    completedWithError:&completedWithError
     completionHandler:completionHandler];

    if (completed) {
        SecTrustSetPolicies(trust, originalPolicies);
        [self logWithFormat:@"Evaluate completed by successful system CRL check"];
        return TRUE;
    }

    // Unfortunately relax our requirements

    [self tryFallback:trust
     originalPolicies:originalPolicies
            completed:&completed
   completedWithError:&completedWithError
    completionHandler:completionHandler];

    if (completed) {
        SecTrustSetPolicies(trust, originalPolicies);
        [self logWithFormat:@"Completed with fallback system check"];
        return TRUE;
    }

    SecTrustSetPolicies(trust, originalPolicies);
    // Reject the protection space.
    // Do not use NSURLSessionAuthChallengePerformDefaultHandling because it can trigger
    // plaintext OCSP requests.
    completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);

    return FALSE;
}

#pragma mark - Revocation checks

/// Helper to eliminate boilerplate
- (void)evaluateWithPolicy:(SecPolicyRef)policy
          originalPolicies:(CFArrayRef)originalPolicies
                     trust:(SecTrustRef)trust
                 completed:(BOOL*)completed
        completedWithError:(BOOL*)completedWithError
         completionHandler:(AuthCompletion)completionHandler {

    CFIndex policyCount = CFArrayGetCount(originalPolicies);
    CFMutableArrayRef newPolicies = CFArrayCreateMutableCopy(NULL, policyCount+1, originalPolicies);
    CFArrayAppendValue(newPolicies, policy);

    OSStatus s = SecTrustSetPolicies(trust, newPolicies);
    CFRelease(newPolicies);
    CFRelease(policy);
    if (s != 0) {
        [self logWithFormat:@"Unexpected result code from SecTrustSetPolicies %d", s];
        *completed = FALSE;
        *completedWithError = FALSE;
        return;
    }

    [self evaluateTrust:trust
              completed:completed
     completedWithError:completedWithError
      completionHandler:completionHandler];
}

/// Uses default checking with no remote calls.
/// Succeeds if there is a pinned OCSP response or one was cached by the system.
- (void)trySystemOCSPNoRemote:(SecTrustRef)trust
             originalPolicies:(CFArrayRef)originalPolicies
                    completed:(BOOL*)completed
           completedWithError:(BOOL*)completedWithError
            completionHandler:(AuthCompletion)completionHandler {
    SecPolicyRef policy = SecPolicyCreateRevocation(kSecRevocationOCSPMethod |
                                                    kSecRevocationRequirePositiveResponse |
                                                    kSecRevocationNetworkAccessDisabled);
    [self evaluateWithPolicy:policy
            originalPolicies:originalPolicies
                       trust:trust
                   completed:completed
          completedWithError:completedWithError
           completionHandler:completionHandler];

    return;
}

/// Evaluate response from OCSP cache
- (void)evaluateOCSPCacheResult:(NSArray<OCSPCacheLookupResult*>*)results
               originalPolicies:(CFArrayRef)originalPolicies
                evictedResponse:(BOOL*)evictedResponse
                          trust:(SecTrustRef)trust
                      completed:(BOOL*)completed
             completedWithError:(BOOL*)completedWithError
              completionHandler:(AuthCompletion)completionHandler {

    *completed = FALSE;
    *completedWithError = FALSE;
    *evictedResponse = FALSE;

    NSMutableArray *ocspResponses = [[NSMutableArray alloc] init];

    for (OCSPCacheLookupResult* result in results) {
        if (result.err != nil) {
            [self logWithFormat:@"Error from OCSPCache %@", result.err];
        } else {

            if (result.cached) {
                [self logWithFormat:@"Got cached OCSP response"];
            } else {
                [self logWithFormat:@"Fetched OCSP response from remote"];
            }

            [ocspResponses addObject:result.response.data];
            CFDataRef d = (__bridge CFDataRef)result.response.data;
            SecTrustSetOCSPResponse(trust, d);
        }
    }

    if ([ocspResponses count] > 0) {
        SecTrustSetOCSPResponse(trust, (__bridge CFArrayRef)ocspResponses);
    } else {
        // Already checked this case in the no remote OCSP check
        return;
    }

    SecPolicyRef policy = SecPolicyCreateRevocation(kSecRevocationOCSPMethod |
                                                    kSecRevocationRequirePositiveResponse |
                                                    kSecRevocationNetworkAccessDisabled);

    [self evaluateWithPolicy:policy
            originalPolicies:originalPolicies
                       trust:trust
                   completed:completed
          completedWithError:completedWithError
           completionHandler:completionHandler];

    if (!*completed || (*completed && *completedWithError)) {
        [self logWithFormat:@"Evaluate failed with OCSP response from cache"];

        // Remove the cached value. There is no way to tell if it was the reason for
        // rejection since the iOS OCSP cache is a black box; so we should remove it
        // just incase the response was invalid or expired.
        NSInteger certCount = SecTrustGetCertificateCount(trust);
        if (certCount > 0) {
            // Evict responses for all certificates except the root since there
            // will be no OCSP response.
            for (int i = 0; i < certCount-1; i ++) {
                SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust, i);
                [self->ocspCache removeCacheValueForCert:cert];
            }
            *evictedResponse = YES;
        } else {
            [self logWithFormat:@"No certs in trust"];
        }
    }

    return;
}

/// Try default system CRL checking with a positive response required
- (void)trySystemCRL:(SecTrustRef)trust
    originalPolicies:(CFArrayRef)originalPolicies
           completed:(BOOL*)completed
  completedWithError:(BOOL*)completedWithError
   completionHandler:(AuthCompletion)completionHandler {
    SecPolicyRef policy = SecPolicyCreateRevocation(kSecRevocationCRLMethod |
                                                    kSecRevocationRequirePositiveResponse);

    [self evaluateWithPolicy:policy
            originalPolicies:originalPolicies
                       trust:trust
                   completed:completed
          completedWithError:completedWithError
           completionHandler:completionHandler];

    if (*completed) {
        [self logWithFormat:@"Evaluate completed by successful CRL check"];
        return;
    }
}

/// Basic system check with positive response not required
- (void)tryFallback:(SecTrustRef)trust
   originalPolicies:(CFArrayRef)originalPolicies
          completed:(BOOL*)completed
 completedWithError:(BOOL*)completedWithError
  completionHandler:(AuthCompletion)completionHandler {

    SecPolicyRef policy = SecPolicyCreateRevocation(kSecRevocationCRLMethod);

    [self evaluateWithPolicy:policy
            originalPolicies:originalPolicies
                       trust:trust
                   completed:completed
          completedWithError:completedWithError
           completionHandler:completionHandler];

    if (*completed) {
        [self logWithFormat:@"Evaluate completed by fallback revocation check"];
        return;
    }
}

/// Evaluate trust.
/// Revocation policy should already be set with `SecPolicyCreateRevocation` at this point.
- (void)evaluateTrust:(SecTrustRef)trust
            completed:(BOOL*)completed
   completedWithError:(BOOL*)completedWithError
    completionHandler:(AuthCompletion)completionHandler {

    SecTrustResultType result;
    OSStatus s = SecTrustEvaluate(trust, &result);
    if (s != 0) {
        [self logWithFormat:@"Unexpected result code from SecTrustEvaluate %d", s];
        *completed = FALSE;
        *completedWithError = FALSE;
        return;
    }

    if (result == kSecTrustResultProceed || result == kSecTrustResultUnspecified) {
        NSURLCredential *credential = [NSURLCredential credentialForTrust:trust];
        assert(credential != nil);

        completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
        *completed = TRUE;
        *completedWithError = FALSE;
        return;
    }

    if (result != kSecTrustResultRecoverableTrustFailure) {
        *completed = TRUE;
        *completedWithError = TRUE;
        completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);
        return;
    }

    *completed = FALSE;
    *completedWithError = FALSE;
    return;
}

#pragma mark - Logging

- (void)logWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2) {
    if (self->logger != nil) {
        va_list arguments;

        va_start(arguments, format);
        NSString *message = [[NSString alloc] initWithFormat:format arguments:arguments];
        va_end(arguments);

        self->logger(message);
    }
}

@end
