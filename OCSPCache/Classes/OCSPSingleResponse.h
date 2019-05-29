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
#import <openssl/ocsp.h>
#import "OCSPError.h"

NS_ASSUME_NONNULL_BEGIN

@interface OCSPSingleResponse : NSObject

@property (readonly, assign, nonatomic) OCSP_SINGLERESP *response;

- (instancetype)initWithResponse:(OCSP_SINGLERESP*)response;

- (Error*)expired:(BOOL*)expired;

+ (Error*)expiredWithResponse:(OCSP_SINGLERESP*)response expired:(BOOL*)expired;

- (Error*)thisUpdate:(NSDate*__nullable*__nonnull)thisUpdate
          nextUpdate:(NSDate*__nullable*__nonnull)nextUpdate;

+ (Error*)datesFromResponse:(OCSP_SINGLERESP*)response
                 thisUpdate:(NSDate*__nullable*__nonnull)thisUpdate
                 nextUpdate:(NSDate*__nullable*__nonnull)nextUpdate;

@end

NS_ASSUME_NONNULL_END
