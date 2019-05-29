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

#import "OCSPSingleResponse.h"

@interface OCSPSingleResponse ()

@property (assign, nonatomic) OCSP_SINGLERESP *response;

@end

@implementation OCSPSingleResponse

- (instancetype)initWithResponse:(OCSP_SINGLERESP*)response {
    self = [super init];

    if (self) {
        self.response = response;
    }

    return self;
}

- (void)dealloc {
    if (self.response) {
        OCSP_SINGLERESP_free(self.response);
    }
}

- (Error*)expired:(BOOL*)expired {
    return [OCSPSingleResponse expiredWithResponse:self.response expired:expired];
}

+ (Error*)expiredWithResponse:(OCSP_SINGLERESP*)response expired:(BOOL*)expired {
    int pday, psec, ret;

    ret = ASN1_TIME_diff(&pday, &psec, NULL, response->nextUpdate);
    if (ret == 0) {
        // Error pday and psec will be unset
        // Return code set:
        // https://github.com/openssl/openssl/blob/b34cf4eb616446a1ee7bd0db0a625edf25047342/crypto/o_time.c#L320
        return @"non-zero return code from AS1_TIME_diff()";
    }

    if (pday < 0 || psec < 0) {
        *expired = TRUE;
        return nil;
    }

    *expired = FALSE;
    return nil;
}

- (NSString*)thisUpdate:(NSDate**)thisUpdate
             nextUpdate:(NSDate**)nextUpdate {
    return [OCSPSingleResponse datesFromResponse:self.response
                                      thisUpdate:thisUpdate
                                      nextUpdate:nextUpdate];
}

+ (Error*)datesFromResponse:(OCSP_SINGLERESP*)response
                 thisUpdate:(NSDate**)thisUpdate
                 nextUpdate:(NSDate**)nextUpdate {

    unsigned char *t = ASN1_STRING_data(response->thisUpdate);
    unsigned char *n = ASN1_STRING_data(response->nextUpdate);

    NSString *thisUpdateISO8601 = [NSString stringWithFormat:@"%s", t];
    NSString *nextUpdateISO8601 = [NSString stringWithFormat:@"%s", n];

    free(t);
    free(n);

    // thisUpdate and nextUpdate are in GeneralizedTime:
    // https://tools.ietf.org/html/rfc2560#section-4.2.1
    //
    // GeneralizedTime format:
    // https://tools.ietf.org/html/rfc5280#section-4.1.2.5.2
    //
    // According to
    // https://www.openssl.org/docs/man1.1.1/man3/ASN1_TIME_to_generalizedtime.html
    // YYMMDDHHMMSSZ is also supported by GeneralizedTime.
    //
    // Format string mapped by following:
    // https://nsdateformatter.com/ and
    // https://www.unicode.org/reports/tr35/tr35-dates.html#Date_Format_Patterns
    NSDateFormatter *formatter = [OCSPSingleResponse generalizedTimeDateFormat1];

    *thisUpdate = [formatter dateFromString:thisUpdateISO8601];
    *nextUpdate = [formatter dateFromString:nextUpdateISO8601];

    if (*thisUpdate == NULL || *nextUpdate == NULL) {
        NSDateFormatter *formatter = [OCSPSingleResponse generalizedTimeDateFormat2];
        if (*thisUpdate == NULL) {
            *thisUpdate = [formatter dateFromString:thisUpdateISO8601];
        }
        if (*nextUpdate == NULL) {
            *nextUpdate = [formatter dateFromString:nextUpdateISO8601];
        }
    }

    if (*thisUpdate == NULL || *nextUpdate == NULL) {
        return @"Failed to parse thisUpdate and nextUpdate in OCSP_SINGLERESP";
    }

    return nil;
}

#pragma mark - Helpers

+ (NSDateFormatter*)generalizedTimeDateFormat1 {
    return [OCSPSingleResponse dateFormatterHelper:@"yyyyMMddHHmmssZ"];
}

+ (NSDateFormatter*)generalizedTimeDateFormat2 {
    return [OCSPSingleResponse dateFormatterHelper:@"yyMMddHHmmssZ"];
}

+ (NSDateFormatter*)dateFormatterHelper:(NSString*)dateFormat {
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    NSLocale *enUSPOSIXLocale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    [formatter setLocale:enUSPOSIXLocale];
    [formatter setTimeZone:[NSTimeZone timeZoneForSecondsFromGMT:0]];
    [formatter setDateFormat:dateFormat];

    return formatter;
}

@end
