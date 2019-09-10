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
#import "ErrorT.h"

NS_ASSUME_NONNULL_BEGIN

/**
 ErrorTs is a convenience wrapper for accumulating ErrorT in a list.
 Mostly obviating the need to use NSArray directly.
 */
@interface ErrorTs : NSObject

/**
 Accumulated errors.
 */
@property (readonly, strong, nonatomic) NSArray<ErrorT*>* errors;

/**
 @return True if errors array is non-empty.
 */
- (BOOL)error;

/**
 Append underlying error arrays.

 @param x ErrorTs to append.
 */
- (void)mappend:(ErrorTs*)x;

/**
 Append underlying error arrays after
 adding context to the argument ErrorTs
 structure. See ErrorT:addErrors:withContext.

 @param x ErrorTs to append.
 @param s Context string.
 */
- (void)mappendWithContext:(ErrorTs*)x context:(NSString*)s;

/// Adding errors
- (void)addError:(ErrorT*)error;
- (void)addErrorWithString:(NSString*)s;
- (void)addErrorWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);

/**
 Add context to error tree.
 See ErrorT:addErrors:withContext.

 @param s Context string.
 */
- (void)addContextIfError:(NSString*)s;

/**
 [a] -> (a -> [b]) -> [b]

 Apply reduceErrors to each error and then
 concat the results.

 See ErrorT:reduceErrors.

 @return Array of reduced error strings.
 */
- (NSArray<NSString*>*)flattenedAndReducedErrors;

/**
 [a] -> (a -> [b]) -> [b]

 Apply reduceErrors to each error and then
 concat the results.

 See ErrorT:reduceErrors.

 @param sep Errors are reduced with the separator.
 @return Array of reduced error strings.
 */
- (NSArray<NSString*>*)flattenedAndReducedErrorsWithSeparator:(NSString*)sep;

@end

NS_ASSUME_NONNULL_END
