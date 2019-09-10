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

#import "OCSPRequestService.h"
#import <openssl/ocsp.h>
#import "OCSPResponse.h"
#import "RACDisposable.h"
#import "RACReplaySubject.h"
#import "RACSequence.h"
#import "NSArray+RACSequenceAdditions.h"

NSErrorDomain _Nonnull const OCSPRequestServiceErrorDomain = @"OCSPRequestServiceErrorDomain";

@implementation OCSPRequestService

// See comment in header
+ (RACSignal<NSObject*>*)getSuccessfulOCSPResponse:(NSArray<NSURL*>*)ocspURLs
                                   ocspRequestData:(NSData*)ocspRequestData
                                           session:(NSURLSession *_Nullable)session
                                             queue:(dispatch_queue_t)queue
{
    assert([ocspURLs count] != 0);

    return [RACSignal createSignal:^RACDisposable *(id<RACSubscriber>  _Nonnull subscriber) {
        RACSequence *urls = ocspURLs.rac_sequence;

        RACSignal *signal =
        [[[urls signal]
         flattenMap:^__kindof RACSignal * _Nullable(NSURL *url) {
             return [OCSPRequestService ocspRequest:url
                                    ocspRequestData:ocspRequestData
                                      session:session
                                              queue:queue];
         }]
         takeUntilBlock:^BOOL(id  _Nullable x) {
             static int requestCount = 0;
             if ([x isKindOfClass:[OCSPResponse class]]) {
                 if ([x success]) {
                     // Successful response, stop making requests and complete
                     [subscriber sendNext:x];
                     [subscriber sendCompleted];
                 }
             }

             requestCount++;

             if (requestCount == [ocspURLs count]) {
                 // No successful response could be obtained, send an error
                 NSError *error =
                 [NSError errorWithDomain:OCSPRequestServiceErrorDomain
                                     code:OCSPRequestServiceErrorCodeNoSuccessfulResponse
                                 userInfo:@{NSLocalizedDescriptionKey:@"No successful subscriber"}];
                 [subscriber sendError:error];
                 return TRUE;
             }

             return FALSE;
         }];

        [signal subscribeCompleted:^{
            // Kick off cold signal
        }];

        return nil;
    }];
}

/// See comment in header
+ (RACSignal<OCSPResponse*>*)ocspRequest:(NSURL*)ocspURL
                         ocspRequestData:(NSData*)OCSPRequestData
                                 session:(NSURLSession*)session
                                   queue:(dispatch_queue_t)queue
{
    return [RACSignal createSignal:^RACDisposable *(id<RACSubscriber>  _Nonnull subscriber) {
        NSError *e = nil;

        NSURLSession *sessionForRequest;

        if (session) {
            sessionForRequest = session;
        } else {
            NSURLSessionConfiguration *config =
            [NSURLSessionConfiguration ephemeralSessionConfiguration];

            sessionForRequest = [NSURLSession sessionWithConfiguration:config];
        }

        // Make an OCSP request with the POST method.
        // OCSP POST request format: https://tools.ietf.org/html/rfc2560#appendix-A.1.1

        NSMutableURLRequest *ocspReq = [NSMutableURLRequest requestWithURL:ocspURL];
        ocspReq.HTTPMethod = @"POST";
        [ocspReq addValue:@"application/ocsp-request" forHTTPHeaderField:@"Content-Type"];
        [ocspReq setHTTPBody:OCSPRequestData];

        NSURLSessionDataTask *dataTask =
        [sessionForRequest dataTaskWithRequest:ocspReq
                             completionHandler:^(NSData * _Nullable data,
                                                 NSURLResponse * _Nullable response,
                                                 NSError * _Nullable error) {
            if (e != nil) {
                NSError *error =
                [NSError errorWithDomain:OCSPRequestServiceErrorDomain
                                    code:OCSPRequestServiceErrorCodeRequestFailed
                                userInfo:@{NSLocalizedDescriptionKey:@"OCSP request failed",
                                           NSUnderlyingErrorKey:e}];
                [subscriber sendNext:error];
                [subscriber sendCompleted];
                return;
            }

            OCSPResponse *r = [[OCSPResponse alloc] initWithData:data];
            if (!r) {
                // Invalid OCSP Response Data
                NSError *error =
                [NSError errorWithDomain:OCSPRequestServiceErrorDomain
                                    code:OCSPRequestServiceErrorCodeInvalidResponseData
                                userInfo:@{NSLocalizedDescriptionKey:@"Invalid OCSP response data"}];
                [subscriber sendNext:error];
                [subscriber sendCompleted];
            }

            [subscriber sendNext:r];
            [subscriber sendCompleted];
        }];
        [dataTask resume];

        return [RACDisposable disposableWithBlock:^{
            [dataTask cancel];
        }];
    }];
}

@end
