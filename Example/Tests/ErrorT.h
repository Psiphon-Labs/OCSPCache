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

NS_ASSUME_NONNULL_BEGIN

/**
 Error strings stored in a tree structure. This allows us to bubble up errors while
 appending context to each set of errors. Traversing the tree to each leaf while
 appending the error strings gives us the context of each error -- similar to a stack
 trace.

 The motivation is that XCT... test assertions in shared test code make it hard to
 map each error back to the originating test. ErrorT allows us to provide context
 to each error and bubble them up for assertion with XCTFail(); this allows all
 errors to be collected at the top level and the tree structure allows us to map them
 back to the epicenter.

 NOTE: it would be better to use a generic tree structure which would allow us to
       customize the error type -- where a function (a -> a -> a) is given.
 */
@interface ErrorT : NSObject

/**
 Error or context at the current node.
 */
@property (readonly, nonatomic, strong) NSString *error;

/**
 Underlying errrors.
 */
@property (readonly, nonatomic, strong) NSArray<ErrorT*> *errors;

+ (instancetype)error:(NSString*)error;
+ (instancetype)errorWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);
- (instancetype)initWithErrorString:(NSString*)s;

- (void)addError:(ErrorT*)error;
- (void)addErrorWithString:(NSString*)s;
- (void)addErrorWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2);
- (void)addErrors:(NSArray<ErrorT*>*)errors;

/// Add errors and then make them the children of a new node with an error of `context`.
- (void)addErrors:(NSArray<ErrorT*>*)errors withContext:(NSString*)context;

/**
 For each path of root->leaf combine
 the error of each node with the separator
 ":" and return an array of the resulting strings.

 Nodes are combined with the operation a ++ ":" ++ b.

 (A, (B, C)) becomes ["A:B", "A:C"]

 @return Array of strings resulting from reduce operation.
 */
- (NSArray<NSString*>*)reduceErrors;

/**
 For each path of root->leaf combine
 the error of each node with the separator
 and return an array of the resulting strings.

 Nodes are combined with the operation a ++ sep ++ b.

 (A, (B, C)) with sep="-" becomes ["A-B", "A-C"]

 @param separator Seperator to combine each pair of errors with.
 @return Array of strings resulting from reduce operation.
 */
- (NSArray<NSString*>*)reduceErrorsWithSeparator:(NSString*)separator;

@end

NS_ASSUME_NONNULL_END
