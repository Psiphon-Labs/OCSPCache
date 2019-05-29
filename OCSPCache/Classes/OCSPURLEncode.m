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

#import "OCSPURLEncode.h"

@implementation URLEncode

// Encode all reserved characters. See: https://stackoverflow.com/a/34788364.
//
// From RFC 3986 (https://www.ietf.org/rfc/rfc3986.txt):
//
//   2.3.  Unreserved Characters
//
//   Characters that are allowed in a URI but do not have a reserved
//   purpose are called unreserved.  These include uppercase and lowercase
//   letters, decimal digits, hyphen, period, underscore, and tilde.
//
//   unreserved  = ALPHA / DIGIT / "-" / "." / "_" / "~"
+ (NSString*)encode:(NSString*)url {
    NSCharacterSet *queryParamCharsAllowed = [NSCharacterSet
                                              characterSetWithCharactersInString:
                                              @"abcdefghijklmnopqrstuvwxyz"
                                              "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                              "0123456789"
                                              "-._~"];

    return [url stringByAddingPercentEncodingWithAllowedCharacters:queryParamCharsAllowed];
}

@end
