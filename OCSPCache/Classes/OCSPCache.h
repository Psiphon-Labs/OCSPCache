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
#import "OCSPResponse.h"

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const OCSPCacheErrorDomain;

/// Error codes which can be returned from OCSPCache in OCSPCacheLookupResult
typedef NS_ERROR_ENUM(OCSPCacheErrorDomain, OCSPCacheErrorCode) {

    /*!
     * Unknown error. The cache has entered an invalid state.
     */
    OCSPCacheErrorCodeUnknown = -1,

    /*!
     * The cache was provided an invalid trust object as an argument.
     * @code
     * // Underlying error will be set with more information
     * [error.userInfo objectForKey:NSUnderlyingErrorKey]
     * @endcode
     */
    OCSPCacheErrorCodeInvalidTrustObject = 1,

    /*!
     * The cache encountered an error while constructing the OCSP requests.
     * @code
     * // Underlying error will be set with more information
     * [error.userInfo objectForKey:NSUnderlyingErrorKey]
     * @endcode
     */
    OCSPCacheErrorConstructingOCSPRequests,

    /*!
     * No successful OCSP response could be obtained.
     */
    OCSPCacheErrorCodeNoSuccessfulResponse,

    /*!
     * Timeout was exceeded before a successful OCSP response could be obtained.
     */
    OCSPCacheErrorCodeLookupTimedOut,
};

/// Cache lookup result
@interface OCSPCacheLookupResult : NSObject

/*!
 * A valid OCSP response with the status code indicating success.
 * See https://tools.ietf.org/html/rfc6960#section-4.2.1 for a list of OCSP response status codes.
 */
@property (readonly, strong, nonatomic) OCSPResponse *response;

/*!
 * Error of OCSPCacheErrorDomain. If set, other members should be ignored.
 */
@property (readonly, strong, nonatomic) NSError *err;

/*!
 * If TRUE, an OCSP response was found in the cache and returned.
 * If FALSE, an OCSP response was not found in the cache and one had to be obtained with a network
 * request to one of the OCSP servers listed in the Certificate Authority Information Access X.509v3
 * extension within the certificate.
 */
@property (readonly, assign, nonatomic) BOOL cached;

@end

/// Cache which facilitates making OCSP requests and caching OCSP responses.
@interface OCSPCache : NSObject

/*!
 Initalize OCSPCache with logger.

 @param logger Logger for emitting diagnostic information. The provided block is called on a serial
 queue. Logs may include personally identifying information (PII) through errors generated by the
 networking framework; logging should only be used for testing. TODO: implement log levels to
 exclude potentially sensitive logs.
 @return The OCSPCache instance.
 */
- (instancetype)initWithLogger:(void (^__nonnull)(NSString*logLine))logger;


/*!
 Initalize OCSPCache with logger and load persisted cache data from user defaults.

 @param logger Logger for emitting diagnostic information. The provided block is called on a serial
 queue. Logs may include personally identifying information (PII) through errors generated by the
 networking framework; logging should only be used for testing. TODO: implement log levels to
 exclude potentially sensitive logs.
 @param userDefaults User defaults instance which should be used for loading persisted cache data.
 @param key Key in the provided user defaults instance which the persisted cache data is to be
 loaded from.
 @return The OCSPCache instance.
 */
- (instancetype)initWithLogger:(void (^__nonnull)(NSString*logLine))logger
       andLoadFromUserDefaults:(NSUserDefaults*)userDefaults
                       withKey:(NSString*)key;

/*!
 Persist cache data to user defaults.

 @param userDefaults User defaults instance which should be used for loading persisted cache data.
 @param key Key in the provided user defaults instance which the persisted cache data is to be
 loaded from.
 */
- (void)persistToUserDefaults:(NSUserDefaults*)userDefaults
                      withKey:(NSString*)key;


/*!
 Obtain an OCSP response for the provided certificate.

 If a cached value is found, it is returned.

 If the value is not cached, network requests are made to obtain a valid OCSP response. A valid OCSP
 response is one with the status code indicating success.

 See https://tools.ietf.org/html/rfc6960#section-4.2.1 for a list of OCSP response status codes.

 @param secTrustRef Target trust reference. Must include the target certificate and the certificate
 of its issuer.
 @param timeout Timeout in seconds. If the lookup exceeds the provided timeout, an error with the
 code OCSPCacheErrorCodeLookupTimedOut is returned. A timeout value of 0 indicates that there should
 be no timeout.
 @param modifyOCSPURL Block which updates each OCSP URL. This is an opportunity for the caller to:
 update the URL to point through a local proxy, whitelist the URL if needed, etc. If the provided
 block returns nil, the original URL is used.
 @param session Session with which to perform OCSP requests. This is an opportunity for the caller
 to specify a proxy to be used by the OCSP requests. If nil, a session with
 `ephemeralSessionConfiguration` is created and used.
 @param completion Completion handler which is called when the lookup completes. If result.err is
 set then the other values should be ignored.
 */
- (void)lookup:(SecTrustRef)secTrustRef
    andTimeout:(NSTimeInterval)timeout
 modifyOCSPURL:(NSURL* (^__nullable)(NSURL *url))modifyOCSPURL
       session:(NSURLSession*__nullable)session
    completion:(void (^)(OCSPCacheLookupResult *result))completion;

/// Blocking lookup
- (OCSPCacheLookupResult*)lookup:(SecTrustRef)secTrustRef
                      andTimeout:(NSTimeInterval)timeout
                   modifyOCSPURL:(NSURL* (^__nullable)(NSURL *url))modifyOCSPURL
                         session:(NSURLSession*__nullable)session;

/*!
 Obtain an OCSP response for the provided certificate.

 If a cached value is found, it is returned.

 If the value is not cached, network requests are made to obtain a valid OCSP response. A valid OCSP
 response is one with the status code indicating success.

 See https://tools.ietf.org/html/rfc6960#section-4.2.1 for a list of OCSP response status codes.

 @param secCertRef Target certificate.
 @param issuerRef Issuer certificate of the target certificate.
 @param timeout Timeout in seconds. If the lookup exceeds the provided timeout, an error with the
 code OCSPCacheErrorCodeLookupTimedOut is returned. A timeout value of 0 indicates that there should
 be no timeout.
 @param modifyOCSPURL Block which updates each OCSP URL. This is an opportunity for the caller to:
 update the URL to point through a local proxy, whitelist the URL if needed, etc. If the provided
 block returns nil, the original URL is used.
 @param session Session with which to perform OCSP requests. This is an opportunity for the caller
 to specify a proxy to be used by the OCSP requests.  If nil, a session with
 `ephemeralSessionConfiguration` is created and used.
 @param completion Completion handler which is called when the lookup completes. If result.err is
 set then the other values should be ignored.
 */
- (void)lookup:(SecCertificateRef)secCertRef
    withIssuer:(SecCertificateRef)issuerRef
    andTimeout:(NSTimeInterval)timeout
 modifyOCSPURL:(NSURL* (^__nullable)(NSURL *url))modifyOCSPURL
       session:(NSURLSession*__nullable)session
    completion:(void (^)(OCSPCacheLookupResult *result))completion;

/// Blocking lookup
- (OCSPCacheLookupResult*)lookup:(SecCertificateRef)secCertRef
                      withIssuer:(SecCertificateRef)issuerRef
                      andTimeout:(NSTimeInterval)timeout
                   modifyOCSPURL:(NSURL* (^__nullable)(NSURL *url))modifyOCSPURL
                         session:(NSURLSession*__nullable)session;

/*!
 Set the cache value for a certificate.

 @note This function is primarily used for testing.
 @param secCertRef Certificate which the data corresponds to.
 @param data The data to cache. Must be a valid OCSP response.
 */
- (void)setCacheValueForCert:(SecCertificateRef)secCertRef data:(NSData*)data;

/*!
 Remove the cache value for a certificate.

 @param secCertRef Certificate which the value in the cache corresponds to.
 @return Returns TRUE if a value was evicted; otherwise FALSE.
 */
- (BOOL)removeCacheValueForCert:(SecCertificateRef)secCertRef;

@end

NS_ASSUME_NONNULL_END
