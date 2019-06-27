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

// See comment in header
+ (RACSignal<NSObject*>*)getOCSPData:(NSArray<NSURL*>*)ocspURLs
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
                NSURLResponse *resp = nil;
                NSError *e = nil;

                NSURLRequest *ocspReq = [NSURLRequest requestWithURL:ocspURL];

                NSData *data = [NSURLConnection sendSynchronousRequest:ocspReq
                                                     returningResponse:&resp
                                                                 error:&e];
                if (e != nil) {
                    NSError *error =
                    [NSError errorWithDomain:OCSPServiceErrorDomain
                                        code:OCSPServiceErrorCodeRequestFailed
                                    userInfo:@{NSLocalizedDescriptionKey:@"OCSP request failed",
                                               NSUnderlyingErrorKey:e}];
                    [subscriber sendNext:error];
                    continue;
                }

                OCSPResponse *r = [[OCSPResponse alloc] initWithData:data];
                if (!r) {
                    // Invalid OCSP Response Data
                    NSError *error =
                    [NSError errorWithDomain:OCSPServiceErrorDomain
                                        code:OCSPServiceErrorCodeInvalidResponseData
                                    userInfo:@{NSLocalizedDescriptionKey:@"Invalid subscriber data"}];
                    [subscriber sendNext:error];
                    continue;
                }

                [subscriber sendNext:r];

                if ([r status] == OCSP_RESPONSE_STATUS_SUCCESSFUL) {
                    return;
                }
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
