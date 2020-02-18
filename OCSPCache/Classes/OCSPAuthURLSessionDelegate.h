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
#import "OCSPCache.h"

NS_ASSUME_NONNULL_BEGIN

typedef void (^AuthCompletion)(NSURLSessionAuthChallengeDisposition, NSURLCredential *__nullable);

/*!
 * OCSPAuthURLSessionDelegate implements URLSession:task:didReceiveChallenge:completionHandler:
 * of the NSURLSessionDelegate protocol.
 *
 * The main motivation of OCSPAuthURLSessionDelegate is to ensure that OCSP requests are not sent in
 * plaintext by the system when the desire is to proxy all network traffic. Plaintext OCSP requests
 * are problematic because they leak the identity of the certificate being verified.
 *
 * If the policy object for checking the revocation of certificates is created with
 * SecPolicyCreateRevocation(kSecRevocationOCSPMethod | ...), and network access is allowed
 * (the kSecRevocationNetworkAccessDisabled flag is not provided), a plaintext OCSP request over
 * HTTP is triggered when SecTrustEvaluate() is called. This request does not respect NSURLProtocol
 * subclassing.
 *
 * The solution is to inspect each X.509 certificate for the Online Certificate Status Protocol
 * (1.3.6.1.5.5.7.48.1) Authority Information Access Method, which contains the locations (URLs) of
 * the OCSP servers; then OCSP requests can be made to these servers through local proxies.
 *
 * Note: OCSPAuthURLSessionDelegate only checks revocation status with OCSP.
 *
 * Note: The OCSP Authority Information Access Method is found in the Certificate Authority
 *       Information Access (1.3.6.1.5.5.7.1.1) X.509v3 extension --
 *       https://tools.ietf.org/html/rfc2459#section-4.2.2.1.
 */
@interface OCSPAuthURLSessionDelegate : NSObject <NSURLSessionDelegate, NSURLSessionTaskDelegate>

/// Initialize OCSPAuthURLSessionDelegate.
/// @param logger logger Logger for emitting diagnostic information. Logging should only be used for
/// testing since it emits the URLs corresponding to the certificate being validated.
/// @param ocspCache OCSPCache to use for making OCSP requests and caching OCSP responses.
/// @param modifyOCSPURL Block which updates each OCSP URL. This is an opportunity for the caller to:
/// update the URL to point through a local proxy, whitelist the URL if needed, etc. If the provided
/// block returns nil, the original URL is used.
/// @param session Session with which to perform OCSP requests. This is an opportunity for the
/// caller to specify a proxy to be used by the OCSP requests. If nil, a session with
/// `ephemeralSessionConfiguration` is created and used.
/// @param timeout Timeout in seconds for each set of OCSP requests made for a certificate (often 1
///                request) via OCSPAuthURLSessionDelegate. If the timeout values set in the
///                provided NSURLSession are shorter, then this value is effectively ignored; if no
///                NSURLSession is provided, the same applies for the default timeout values of
///                NSURLSessionConfiguration:ephemeralSessionConfiguration.
-  (instancetype)initWithLogger:(void (^)(NSString*))logger
                      ocspCache:(OCSPCache*)ocspCache
                  modifyOCSPURL:(NSURL* (^__nullable)(NSURL *url))modifyOCSPURL
                        session:(NSURLSession*__nullable)session
                        timeout:(NSTimeInterval)timeout;

/// Evaluate trust object performing certificate revocation checks in the following order:
///   1. OCSP staple
///   2. OCSP cache
///   3. OCSP remote
///   4. CRL with positive response and network
///   5. CRL with network
/// Returns TRUE if the trust was evaulated with a postive response; otherwise returns FALSE.
/// @param trust Target trust reference. Must include the target certificate and the certificate
/// of its issuer.
/// @param completionHandler Completion handler from the NSURLSessionDelegate or NSURLSessionTaskDelegate
/// authentication challenge.
/// @warning The trust object will be modified and is not safe to access until the call completes.
- (BOOL)evaluateTrust:(SecTrustRef)trust
    completionHandler:(AuthCompletion)completionHandler;

/// Evaluate trust object performing certificate revocation checks in the following order:
///   1. OCSP staple
///   2. OCSP cache
///   3. OCSP remote
///   4. CRL with positive response and network
///   5. CRL with network
/// Returns TRUE if the trust was evaulated with a postive response; otherwise returns FALSE.
/// @param trust Target trust reference. Must include the target certificate and the certificate
/// of its issuer.
/// @param modifyOCSPURLOverride Override the block specified when OCSPAuthURLSessionDelegate was initialized. This allows
/// independent tasks to manage their own URL rewriting while sharing the same underlying OCSPAuthURLSessionDelegate.
/// @param sessionOverride Override the session specified when OCSPAuthURLSessionDelegate was
/// initialized. This allows independent tasks to mange the NSURLSession used per trust evaluation.
/// @param completionHandler Completion handler from the NSURLSessionDelegate or NSURLSessionTaskDelegate
/// authentication challenge.
/// @warning The trust object will be modified and is not safe to access until the call completes.
- (BOOL)evaluateTrust:(SecTrustRef)trust
modifyOCSPURLOverride:(NSURL* (^__nullable)(NSURL *url))modifyOCSPURLOverride
      sessionOverride:(NSURLSession*__nullable)sessionOverride
    completionHandler:(AuthCompletion)completionHandler;

/// NSURLSessionDelegate implementation
- (void)URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler;

/// NSURLSessionTaskDelegate implementation
- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *__nullable)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler;

@end

NS_ASSUME_NONNULL_END
