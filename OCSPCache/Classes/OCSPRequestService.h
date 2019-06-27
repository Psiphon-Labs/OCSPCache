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

FOUNDATION_EXPORT NSErrorDomain const OCSPServiceErrorDomain;

/// Error codes which can be returned by OCSPService
typedef NS_ERROR_ENUM(OCSPServiceErrorDomain, OCSPServiceErrorCode) {

    /*!
     * Unknown error.
     */
    OCSPServiceErrorCodeUnknown = -1,

    /*!
     * No URLs provided.
     */
    OCSPServiceErrorCodeNoURLs = 1,

    /*!
     * Failed network request.
     * @code
     * // Underlying error will be set with more information
     * [error.userInfo objectForKey:NSUnderlyingErrorKey]
     * @endcode
     */
    OCSPServiceErrorCodeRequestFailed,

    /*!
     * Invalid data returned from OCSP request.
     * The network request was successful, but the response data
     * could not be deserialized successfully into an OCSP Response.
     */
    OCSPServiceErrorCodeInvalidResponseData,

    /*!
     * No successful OCSP response could be obtained.
     */
    OCSPServiceErrorCodeNoSuccessfulResponse
};

@interface OCSPService : NSObject

/*!
 Cold terminating signal which completes when a successful OCSP response is retrieved. If no successful response can be retrieved, an
 error is returned.

 Emits either OCSPResponse or NSError. Each error and unsuccessful response encountered are emitted, but they do not cause signal
 termination.

 OCSP URLs are attempted in order.

 @param ocspURLs OCSP URLs with base 64 encoded OCSP request data for HTTP GET request. See
 OCSPURL.h.
 @param dispatchQueue Dispatch queue which the network requests should be made on.
 */
+ (RACSignal<NSObject*>*)getOCSPData:(NSArray<NSURL*>*)ocspURLs
                 withOCSPRequestData:(NSData*)OCSPRequestData
                             onQueue:(dispatch_queue_t)dispatchQueue;

@end

NS_ASSUME_NONNULL_END
