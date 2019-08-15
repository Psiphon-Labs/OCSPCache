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

#import "ErrorTs.h"

@interface ErrorTs ()

@property (strong, nonatomic) NSArray<ErrorT*>* errors;

@end

@implementation ErrorTs

- (instancetype)init {
    self = [super init];

    if (self) {
        self.errors = [[NSArray alloc] init];
    }

    return self;
}

- (BOOL)error {
    return [self.errors count] > 0;
}

- (void)mappend:(ErrorTs*)x {
    if (![x error]) {
        return;
    }
    self.errors = [self.errors arrayByAddingObjectsFromArray:x.errors];
}

- (void)mappendWithContext:(ErrorTs*)x context:(NSString*)s {
    [x addContextIfError:s];
    [self mappend:x];
}

- (void)addContextIfError:(NSString*)s {
    if ([self error]) {
        ErrorT *newParent = [ErrorT error:s];
        [newParent addErrors:self.errors];
        self.errors = @[newParent];
    }
}

- (void)addError:(ErrorT*)error {
    self.errors = [self.errors arrayByAddingObject:error];
}

- (void)addErrorWithString:(NSString*)s {
    ErrorT *x = [ErrorT error:s];
    [self addError:x];
}

- (void)addErrorWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2) {
    va_list arguments;
    va_start(arguments, format);
    NSString *s = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);

    [self addErrorWithString:s];
}

- (NSArray<NSString*>*)flattenedAndReducedErrors {
    return [self flattenedAndReducedErrorsWithSeparator:@":"];
}

- (NSArray<NSString*>*)flattenedAndReducedErrorsWithSeparator:(NSString*)sep {
    NSMutableArray *xs = [[NSMutableArray alloc] init];
    for (ErrorT *x in self.errors) {
        [xs addObjectsFromArray:[x reduceErrorsWithSeparator:sep]];
    }

    return xs;
}

@end
