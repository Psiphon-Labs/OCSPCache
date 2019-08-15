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


#import <XCTest/XCTest.h>
#import "ErrorT.h"
#import "ErrorTs.h"

@interface ErrorTTests : XCTestCase

@end

@implementation ErrorTTests

- (void)setUp {
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
}

// Testing ErrorT which represents a tree of error strings
- (void)testErrorT {
    {
        ErrorT *a = [ErrorT error:@"A"];
        NSArray <NSString*>* reducedErrors = [a reduceErrors];
        XCTAssert([[reducedErrors objectAtIndex:0] isEqualToString:@"A"]);
    }
    {
        ErrorT *a = [ErrorT error:@"A"];
        ErrorT *b = [ErrorT error:@"B"];
        ErrorT *c = [ErrorT error:@"C"];
        ErrorT *b1 = [ErrorT error:@"B1"];
        ErrorT *b2 = [ErrorT error:@"B2"];
        [b addErrors:@[b1, b2]];
        [a addErrors:@[b, c]];

        NSArray <NSString*>* reducedErrors = [a reduceErrors];

        XCTAssert([[reducedErrors objectAtIndex:0] isEqualToString:@"A:B:B1"]);
        XCTAssert([[reducedErrors objectAtIndex:1] isEqualToString:@"A:B:B2"]);
        XCTAssert([[reducedErrors objectAtIndex:2] isEqualToString:@"A:C"]);
    }
}

// Testing ErrorTs which is a convenience wrapper around ErrorT which allows the
// accumulation of errors. This allows us to bubble up errors from shared test code and
// then traverse the tree to each leaf while accumulating to trace the source of each
// error.
- (void)testErrorTs {

    // Adding context to the tree

    ErrorTs *xs = [[ErrorTs alloc] init];
    [xs addErrorWithString:@"B"];
    [xs addErrorWithString:@"C"];
    [xs addContextIfError:@"A"];

    NSArray <NSString*>* flattenedAndReducedErrors = [xs flattenedAndReducedErrorsWithSeparator:@"-"];

    XCTAssert([[flattenedAndReducedErrors objectAtIndex:0] isEqualToString:@"A-B"]);
    XCTAssert([[flattenedAndReducedErrors objectAtIndex:1] isEqualToString:@"A-C"]);

    // Adding context and mappending an empty tree

    ErrorTs *ys = [[ErrorTs alloc] init];
    [xs mappendWithContext:ys context:@"Unused context"];
    XCTAssert([xs flattenedAndReducedErrors].count == 2);
}

@end
