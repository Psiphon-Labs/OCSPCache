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

@implementation OCSPAuthURLSessionDelegate {
    void (^logger)(NSString*);
    NSURL* (^modifyOCSPURL)(NSURL *url);
    OCSPCache* ocspCache;
    void (^successfullyValidatedTrust)(SecTrustRef trust);
}

- (instancetype)init {
    self = [super init];

    if (self) {
        self->ocspCache =
        [[OCSPCache alloc] initWithLogger:^(NSString * _Nonnull logLine) {
            NSLog(@"[OCSPCache] %@", logLine);
        }];
    }

    return self;
}

/// See comment in header
-  (instancetype)initWithLogger:(void (^)(NSString*))logger
                      ocspCache:(nonnull OCSPCache *)ocspCache
                  modifyOCSPURL:(nullable NSURL * _Nonnull (^)(NSURL * _Nonnull))modifyOCSPURL {
    self = [super init];

    if (self) {
        self->logger = logger;
        self->ocspCache = ocspCache;
        self->modifyOCSPURL = modifyOCSPURL;
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
- (void)evaluateTrust:(SecTrustRef)trust
    completionHandler:(AuthCompletion)completionHandler {

    [self evaluateTrust:trust modifyOCSPURLOverride:nil completionHandler:completionHandler];
}

/// See comment in header
- (BOOL)evaluateTrust:(SecTrustRef)trust
            modifyOCSPURLOverride:(nullable NSURL * _Nonnull (^)(NSURL * _Nonnull))modifyOCSPURLOverride
                completionHandler:(AuthCompletion)completionHandler {

    NSURL* (^modifyOCSPURL)(NSURL *url);

    if (modifyOCSPURLOverride) {
        modifyOCSPURL = modifyOCSPURLOverride;
    } else {
        modifyOCSPURL = self->modifyOCSPURL;
    }

    BOOL completed;
    BOOL completedWithError;

    // Check if there is a pinned or cached OCSP response

    [self trySystemOCSPNoRemote:trust
                      completed:&completed
             completedWithError:&completedWithError
              completionHandler:completionHandler];

    if (completed) {
        [self logWithFormat:@"Pinned or cached OCSP response found by the system"];
        return TRUE;
    }

    // No pinned OCSP response, try fetching one

    [self logWithFormat:@"Fetching OCSP response through OCSPCache"];

    OCSPCacheLookupResult *result = [self->ocspCache lookup:trust
                                                andTimeout:0
                                             modifyOCSPURL:modifyOCSPURL];

    BOOL evictedResponse;

    [self evaluateOCSPCacheResult:result
                  evictedResponse:&evictedResponse
                         trust:trust
                        completed:&completed
               completedWithError:&completedWithError
                completionHandler:completionHandler];

    if (completed) {
        [self logWithFormat:@"Completed with OCSP response"];
        return TRUE;
    }

    // Check if check failed and a response was evicted from the cache
    if (!completed && evictedResponse && result.cached) {

        // The response may have been evicted if it was expired or invalid. Retry once.

        OCSPCacheLookupResult *result = [self->ocspCache lookup:trust
                                                    andTimeout:0
                                                 modifyOCSPURL:modifyOCSPURL];

        [self evaluateOCSPCacheResult:result
                      evictedResponse:&evictedResponse
                             trust:trust
                            completed:&completed
                   completedWithError:&completedWithError
                    completionHandler:completionHandler];
        if (completed) {
            [self logWithFormat:@"Completed with OCSP response after evict and fetch"];
            return TRUE;
        }
    }

    // Try system CRL check and require a positive response

    [self trySystemCRL:trust
             completed:&completed
    completedWithError:&completedWithError
     completionHandler:completionHandler];

    if (completed) {
        [self logWithFormat:@"Evaluate completed by successful system CRL check"];
        return TRUE;
    }

    // Unfortunately relax our requirements

    [self tryFallback:trust
            completed:&completed
   completedWithError:&completedWithError
    completionHandler:completionHandler];

    if (completed) {
        [self logWithFormat:@"Completed with fallback system check"];
        return TRUE;
    }

    // Reject the protection space.
    // Do not use NSURLSessionAuthChallengePerformDefaultHandling because it can trigger
    // plaintext OCSP requests.
    completionHandler(NSURLSessionAuthChallengeRejectProtectionSpace, nil);

    return FALSE;
}

#pragma mark - Revocation checks

/// Helper to eliminate boilerplate
- (void)evaluateWithPolicy:(SecPolicyRef)policy
                  trust:(SecTrustRef)trust
                 completed:(BOOL*)completed
        completedWithError:(BOOL*)completedWithError
         completionHandler:(AuthCompletion)completionHandler {

    [self evaluateTrust:trust
              completed:completed
     completedWithError:completedWithError
      completionHandler:completionHandler];
}

/// Uses default checking with no remote calls.
/// Succeeds if there is a pinned OCSP response or one was cached by the system.
- (void)trySystemOCSPNoRemote:(SecTrustRef)trust
                    completed:(BOOL*)completed
           completedWithError:(BOOL*)completedWithError
            completionHandler:(AuthCompletion)completionHandler {
    SecPolicyRef policy = SecPolicyCreateRevocation(kSecRevocationOCSPMethod |
                                                    kSecRevocationRequirePositiveResponse |
                                                    kSecRevocationNetworkAccessDisabled);
    [self evaluateWithPolicy:policy
                    trust:trust
                   completed:completed
          completedWithError:completedWithError
           completionHandler:completionHandler];

    return;
}

/// Evaluate response from OCSP cache
- (void)evaluateOCSPCacheResult:(OCSPCacheLookupResult*)result
                evictedResponse:(BOOL*)evictedResponse
                       trust:(SecTrustRef)trust
                      completed:(BOOL*)completed
             completedWithError:(BOOL*)completedWithError
              completionHandler:(AuthCompletion)completionHandler {

    *completed = FALSE;
    *completedWithError = FALSE;
    *evictedResponse = FALSE;

    if (result.err != nil) {
        [self logWithFormat:@"Error from OCSPCache %@", result.err];
        return;
    } else {

        if (result.cached) {
            [self logWithFormat:@"Got cached OCSP response"];
        } else {
            [self logWithFormat:@"Fetched OCSP response from remote"];
        }

        CFDataRef d = (__bridge CFDataRef)result.response.data;
        SecTrustSetOCSPResponse(trust, d);

        SecTrustResultType trustResultType;
        SecTrustEvaluate(trust, &trustResultType);

        [self evaluateTrust:trust
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
                *evictedResponse = YES;
                SecCertificateRef cert = SecTrustGetCertificateAtIndex(trust, 0);
                [self->ocspCache removeCacheValueForCert:cert];
            } else {
                [self logWithFormat:@"No certs in trust"];
            }
        }

        return;
    }
}

/// Try default system CRL checking with a positive response required
- (void)trySystemCRL:(SecTrustRef)trust
           completed:(BOOL*)completed
  completedWithError:(BOOL*)completedWithError
   completionHandler:(AuthCompletion)completionHandler {
    SecPolicyRef policy = SecPolicyCreateRevocation(kSecRevocationCRLMethod |
                                                    kSecRevocationRequirePositiveResponse);

    [self evaluateWithPolicy:policy
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
          completed:(BOOL*)completed
 completedWithError:(BOOL*)completedWithError
  completionHandler:(AuthCompletion)completionHandler {

    SecPolicyRef policy = SecPolicyCreateRevocation(kSecRevocationCRLMethod);

    [self evaluateWithPolicy:policy
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
    SecTrustEvaluate(trust, &result);

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
