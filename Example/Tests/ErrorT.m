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

#import "ErrorT.h"

@interface ErrorT ()

@property (nonatomic, strong) NSArray<ErrorT*> *errors;
@property (nonatomic, strong) NSString *error;

@end

@implementation ErrorT

+ (instancetype)error:(NSString*)s {
    return [[ErrorT alloc] initWithErrorString:s];
}

+ (instancetype)errorWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2) {
    va_list arguments;

    va_start(arguments, format);
    NSString *s = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);

    return [[ErrorT alloc] initWithErrorString:s];
}

- (instancetype)init {
    self = [super init];

    if (self) {
        self.error = @"";
        self.errors = [[NSArray alloc] init];
    }

    return self;
}

- (instancetype)initWithErrorString:(NSString*)s {
    self = [super init];

    if (self) {
        self.error = s;
        self.errors = [[NSArray alloc] init];
    }

    return self;
}

- (instancetype)initWithErrorWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2) {
    self = [super init];

    if (self) {
        va_list arguments;

        va_start(arguments, format);
        NSString *error = [[NSString alloc] initWithFormat:format arguments:arguments];
        va_end(arguments);

        self.error = error;
        self.errors = [[NSArray alloc] init];
    }

    return self;
}

- (void)addError:(ErrorT *)error {
    [self addErrors:@[error]];
}

- (void)addErrorWithString:(NSString *)s {
    ErrorT *x = [[ErrorT alloc] initWithErrorString:s];
    self.errors = [self.errors arrayByAddingObjectsFromArray:@[x]];
}

- (void)addErrorWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1, 2) {
    va_list arguments;

    va_start(arguments, format);
    NSString *s = [[NSString alloc] initWithFormat:format arguments:arguments];
    va_end(arguments);

    [self addErrorWithString:s];
}

- (void)addErrors:(NSArray<ErrorT*>*)errors {
    self.errors = [self.errors arrayByAddingObjectsFromArray:errors];
}

- (void)addErrors:(NSArray<ErrorT*>*)errors withContext:(NSString*)context {
    ErrorT *x = [[ErrorT alloc] initWithErrorString:context];
    [x addErrors:errors];
    [self addErrors:@[x]];
}

- (NSArray<NSString*>*)reduceErrors {
    return [self reduceErrorsWithSeparator:@":"];
}

- (NSArray<NSString*>*)reduceErrorsWithSeparator:(NSString*)separator {

    NSMutableArray <NSString*>* reducedErrors = [[NSMutableArray alloc] init];

    if ([self.errors count] == 0) {
        return @[self.error];
    }

    for (ErrorT *cur in self.errors) {
        NSArray <NSString*>*reducedNestedErrors = [cur reduceErrors];

        NSMutableArray *new = [[NSMutableArray alloc] init];
        for (NSString *error in reducedNestedErrors) {
            NSString *x = [self.error stringByAppendingFormat:@"%@%@", separator, error];
            [new addObject:x];
        }
        [reducedErrors addObjectsFromArray:new];
    }

    return reducedErrors;
}

@end
