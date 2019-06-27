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
#import "RACReplaySubject.h"

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSErrorDomain const OCSPRequestServiceErrorDomain;

/// Error codes which can be returned by OCSPRequestService
typedef NS_ERROR_ENUM(OCSPRequestServiceErrorDomain, OCSPRequestServiceErrorCode) {

    /*!
     * Unknown error.
     */
    OCSPRequestServiceErrorCodeUnknown = -1,

    /*!
     * Failed network request.
     * @code
     * // Underlying error will be set with more information
     * [error.userInfo objectForKey:NSUnderlyingErrorKey]
     * @endcode
     */
    OCSPRequestServiceErrorCodeRequestFailed = 1,

    /*!
     * Invalid data returned from OCSP request.
     * The network request was successful, but the response data
     * could not be deserialized successfully into an OCSP Response.
     */
    OCSPRequestServiceErrorCodeInvalidResponseData,

    /*!
     * No successful OCSP response could be obtained.
     */
    OCSPRequestServiceErrorCodeNoSuccessfulResponse
};

@interface OCSPRequestService : NSObject

/*!
 Cold terminating signal which completes when a successful OCSP response is retrieved. If no successful response can be retrieved, an
 error is returned.

 Emits either OCSPResponse or NSError. Each error and unsuccessful response encountered are emitted, but they do not cause signal
 termination.

 OCSP URLs are attempted in order.

 @param ocspURLs OCSP server URLs.
 @param dispatchQueue Dispatch queue which the network requests should be made on.
 */
+ (RACSignal<NSObject*>*)getSuccessfulOCSPResponse:(NSArray<NSURL*>*)ocspURLs
                                   ocspRequestData:(NSData*)OCSPRequestData
                                     sessionConfig:(NSURLSessionConfiguration*__nullable)sessionConfig
                                             queue:(dispatch_queue_t)dispatchQueue;

/*!
 Cold terminating signal which performs an OCSP request with the POST method.

 Emits either OCSPResponse or NSError and then completes.

 See: https://tools.ietf.org/html/rfc2560#appendix-A.1.1

 @param ocspURL OCSP server URL to make an OCSP request to.
 @param dispatchQueue Dispatch queue which the network requests should be made on.
 */
+ (RACSignal<NSObject*>*)ocspRequest:(NSURL*)ocspURL
                     ocspRequestData:(NSData*)ocspRequestData
                       sessionConfig:(NSURLSessionConfiguration*__nullable)sessionConfig
                               queue:(dispatch_queue_t)dispatchQueue;

@end

NS_ASSUME_NONNULL_END
