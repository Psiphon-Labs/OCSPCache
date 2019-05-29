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

#import "OCSPResponse.h"
#import <openssl/ocsp.h>

@interface OCSPResponse ()

@property (strong, nonatomic) NSData *data;

@end

@implementation OCSPResponse {
    OCSP_RESPONSE *response;
}

- (void)dealloc {
    if (self->response != nil) {
        OCSP_RESPONSE_free(response);
    }
}

/// See comment in header
- (instancetype)initWithData:(NSData*)data {
    self = [super init];

    if (self) {
        self.data = data;
        self->response = [OCSPResponse responseFromData:data];
        if (!self->response) {
            return nil;
        }
    }

    return self;
}

/// See comment in header
- (NSArray<RACThreeTuple<Error*,
                         OCSPSingleResponse*,
                         NSNumber*>*>*)expiredResponses {
    return [OCSPResponse numExpiredResponsesFromResponse:self->response];
}

+ (NSArray<RACThreeTuple<Error*,
                         OCSPSingleResponse*,
                         NSNumber*>*>*)numExpiredResponsesFromResponse:(OCSP_RESPONSE*)r {

    NSMutableArray<RACThreeTuple<Error*,
                                 OCSPSingleResponse*,
                                 NSNumber*>*>* results = [[NSMutableArray alloc] init];

    NSArray<OCSPSingleResponse*>* responses = [OCSPResponse
                                               singleResponsesFromResponse:r];

    for (OCSPSingleResponse *response in responses) {
        BOOL expired;

        Error *e = [response expired:&expired];

        RACThreeTuple<Error*,OCSPSingleResponse*,NSNumber*> *result =
          [RACThreeTuple pack:e:response:[NSNumber numberWithBool:expired]];

        [results addObject:result];
    }

    return results;
}

+ (NSArray<OCSPSingleResponse*>*)singleResponsesFromResponse:(OCSP_RESPONSE*)r {
    NSMutableArray<OCSPSingleResponse*>* responses = [[NSMutableArray alloc] init];

    OCSP_BASICRESP *basicResponse = OCSP_response_get1_basic(r);

    if (!basicResponse) {
        return responses;
    }

    int responseCount = OCSP_resp_count(basicResponse);

    for (int i = 0; i < responseCount; i++) {
        OCSP_SINGLERESP *singleResponseC = OCSP_resp_get0(basicResponse, i);

        OCSPSingleResponse *singleResponse =
          [[OCSPSingleResponse alloc] initWithResponse:singleResponseC];

        [responses addObject:singleResponse];
    }

    return responses;
}

/// See comment in header
- (int)status {
    return [OCSPResponse statusFromResponse:self->response];
}

+ (int)statusFromResponse:(OCSP_RESPONSE*)r {
    int status = OCSP_response_status(r);

    return status;
}

/// See comment in header
- (BOOL)success {
    return [self status] == OCSP_RESPONSE_STATUS_SUCCESSFUL;
}

+ (OCSP_RESPONSE*)responseFromData:(NSData*)data {
    const unsigned char *p = [data bytes];

    OCSP_RESPONSE *r = d2i_OCSP_RESPONSE(NULL, &p, [data length]);

    return r;
}

@end
