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

#import "OCSPService.h"
#import <openssl/ocsp.h>
#import "OCSPResponse.h"
#import "RACReplaySubject.h"

NSErrorDomain _Nonnull const OCSPServiceErrorDomain = @"OCSPServiceErrorDomain";

@implementation OCSPService

/*
 * Check in SecTrustRef (X.509 cert) for Online Certificate Status Protocol (1.3.6.1.5.5.7.48.1)
 * authority information access method. This is found in the
 * Certificate Authority Information Access (1.3.6.1.5.5.7.1.1) X.509v3 extension.
 *
 * A OCSP request is constructed for each OCSP URL within the certificate. An OCSP request using the
 * GET method is constructed as follows:
 * {url}/{url-encoding of base-64 encoding of the DER encoding of the OCSPRequest}
 *
 * OCSP GET request format: https://tools.ietf.org/html/rfc2560#appendix-A.1.1
 * X.509 Authority Information Access: https://tools.ietf.org/html/rfc2459#section-4.2.2.1
 */

// See comment in header
+ (RACSignal<NSObject*>*)getOCSPData:(NSArray<NSURL*>*)ocspURLs
                     withOCSPRequestData:(NSData*)OCSPRequestData
                            onQueue:(dispatch_queue_t)dispatchQueue
{
    return [RACSignal createSignal:^RACDisposable *(id<RACSubscriber>  _Nonnull subscriber) {
        dispatch_async(dispatchQueue, ^{
            if ([ocspURLs count] == 0) {
                NSError *error =
                [NSError errorWithDomain:OCSPServiceErrorDomain
                                    code:OCSPServiceErrorCodeNoURLs
                                userInfo:@{NSLocalizedDescriptionKey:@"No URLs provided"}];
                [subscriber sendError:error];
                return;
            }

            for (NSURL *ocspURL in ocspURLs) {
                NSError *e = nil;

                NSURLSessionConfiguration *config =
                [NSURLSessionConfiguration ephemeralSessionConfiguration];

                NSURLSession *session =
                [NSURLSession sessionWithConfiguration:config
                                              delegate:nil
                                         delegateQueue:NSOperationQueue.currentQueue];

                NSMutableURLRequest *ocspReq = [NSMutableURLRequest requestWithURL:ocspURL];
                ocspReq.HTTPMethod = @"POST";
                [ocspReq addValue:@"application/ocsp-request" forHTTPHeaderField:@"Content-Type"];
                [ocspReq setHTTPBody:OCSPRequestData];

                NSURLSessionDataTask *dataTask =
                [session dataTaskWithRequest:ocspReq
                           completionHandler:^(NSData * _Nullable data,
                                               NSURLResponse * _Nullable response,
                                               NSError * _Nullable error) {
                               if (e != nil) {
                                   NSError *error =
                                   [NSError errorWithDomain:OCSPServiceErrorDomain
                                                       code:OCSPServiceErrorCodeRequestFailed
                                                   userInfo:@{NSLocalizedDescriptionKey:@"OCSP request failed",
                                                              NSUnderlyingErrorKey:e}];
                                   [subscriber sendNext:error];
                               }

                               OCSPResponse *r = [[OCSPResponse alloc] initWithData:data];
                               if (!r) {
                                   // Invalid OCSP Response Data
                                   NSError *error =
                                   [NSError errorWithDomain:OCSPServiceErrorDomain
                                                       code:OCSPServiceErrorCodeInvalidResponseData
                                                   userInfo:@{NSLocalizedDescriptionKey:@"Invalid subscriber data"}];
                                   [subscriber sendNext:error];
                               }

                               [subscriber sendNext:r];

                               if ([r status] == OCSP_RESPONSE_STATUS_SUCCESSFUL) {
                                   return;
                               }
                           }];
                [dataTask resume];
                return; // TEMP
            }

            // No successful response could be obtained
            NSError *error =
            [NSError errorWithDomain:OCSPServiceErrorDomain
                                code:OCSPServiceErrorCodeNoSuccessfulResponse
                            userInfo:@{NSLocalizedDescriptionKey:@"No successful subscriber"}];
            [subscriber sendError:error];
        });

        return nil;
    }];
}

@end
