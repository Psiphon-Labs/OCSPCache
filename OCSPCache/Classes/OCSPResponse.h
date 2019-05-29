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
#import "OCSPError.h"
#import "RACTuple.h"
#import "OCSPSingleResponse.h"

NS_ASSUME_NONNULL_BEGIN

/// Convenience wrapper around OCSP response data
@interface OCSPResponse : NSObject

@property (readonly, strong, nonatomic) NSData *data;

/// Init with OCSP response data. Returns nil if data cannot be deserialized as an OCSP response.
- (instancetype)initWithData:(NSData*)data;

/// Expired responses in OCSP response
- (NSArray<RACThreeTuple<Error*,OCSPSingleResponse*,NSNumber*>*>*)expiredResponses;

/// OCSP response status
- (int)status;

/// OCSP response status indicates success
- (BOOL)success;

@end

NS_ASSUME_NONNULL_END
