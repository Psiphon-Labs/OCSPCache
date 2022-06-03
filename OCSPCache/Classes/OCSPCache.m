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

#import "OCSPCache.h"
#import <CommonCrypto/CommonDigest.h>
#import "OCSPTrustToLeafAndIssuer.h"
#import "OCSPRequestService.h"
#import "OCSPCert.h"
#import "RACScheduler.h"
#import "RACReplaySubject.h"
#import "RACSignal+Operations.h"

NSErrorDomain _Nonnull const OCSPCacheErrorDomain = @"OCSPCacheErrorDomain";

@interface OCSPCacheLookupResult ()

@property (strong, nonatomic) OCSPResponse *response;
@property (strong, nonatomic) NSError *err;
@property (assign, nonatomic) BOOL cached;

@end

@implementation OCSPCacheLookupResult

+ (instancetype)lookupResultWithResponse:(OCSPResponse*)response
                                   error:(NSError*)error
                                  cached:(BOOL)cached {
    OCSPCacheLookupResult *r = [[OCSPCacheLookupResult alloc] init];
    r.response = response;
    r.err = error;
    r.cached = cached;

    return r;
}

@end

@implementation OCSPCache {
    NSMutableDictionary<NSString*, NSData*>* cache;
    NSMutableDictionary<NSString*, RACReplaySubject<OCSPResponse *>*>* pendingResponseCache;
    void (^logger)(NSString*);
    dispatch_queue_t callbackQueue;
    dispatch_queue_t workQueue;
    dispatch_queue_t logQueue;
    RACScheduler * scheduler;
}

- (instancetype)init {
    self = [super init];

    if (self) {
        [self initTasks];
    }

    return self;
}

- (void)initTasks {
    self->cache = [[NSMutableDictionary alloc] init];
    self->pendingResponseCache = [[NSMutableDictionary alloc] init];
    self->callbackQueue = dispatch_queue_create("ca.psiphon.OCSPCache.CallbackQueue",
                                                DISPATCH_QUEUE_CONCURRENT);
    self->logQueue = dispatch_queue_create("ca.psiphon.OCSPCache.LogQueue",
                                           DISPATCH_QUEUE_SERIAL);
    self->workQueue = dispatch_queue_create("ca.psiphon.OCSPCache.WorkQueue",
                                            DISPATCH_QUEUE_CONCURRENT);
    self->scheduler = [RACScheduler schedulerWithPriority:RACSchedulerPriorityHigh
                                                     name:@"ca.psiphon.OCSPCache.Scheduler"];
}

// See comment in header
- (instancetype)initWithLogger:(void (^)(NSString * _Nonnull log))logger {
    self = [super init];

    if (self) {
        [self initTasks];
        self->logger = logger;
    }

    return self;
}

// See comment in header
- (instancetype)initWithLogger:(void (^)(NSString*logLine))logger
       andLoadFromUserDefaults:(NSUserDefaults*)userDefaults
                       withKey:(NSString*)key {
    self = [super init];

    if (self) {
        [self initTasks];
        self->logger = logger;

        id persisted = [userDefaults objectForKey:key];
        if ([persisted isKindOfClass:[NSDictionary class]]) {
            [self->cache addEntriesFromDictionary:(NSDictionary*)persisted];
        }
    }

    return self;
}

// See comment in header
- (void)persistToUserDefaults:(NSUserDefaults*)userDefaults
                      withKey:(NSString*)key {
    @synchronized (self->cache) {
        [userDefaults setObject:self->cache forKey:key];
    }
}

// See comment in header
- (void)lookup:(SecTrustRef)secTrustRef
    andTimeout:(NSTimeInterval)timeout
 modifyOCSPURL:(NSURL* (^__nullable)(NSURL *url))modifyOCSPURL
       session:(NSURLSession*__nullable)session
    completion:(void (^)(OCSPCacheLookupResult *result))completion {

    NSError *e;
    SecCertificateRef leaf;
    SecCertificateRef issuer;

    [OCSPTrustToLeafAndIssuer leafAndIssuerFromSecTrustRef:secTrustRef
                                                      leaf:&leaf
                                                    issuer:&issuer
                                                     error:&e];
    if (e) {
        NSError *error =
        [NSError errorWithDomain:OCSPCacheErrorDomain
                            code:OCSPCacheErrorCodeInvalidTrustObject
                        userInfo:@{NSLocalizedDescriptionKey:@"Invalid trust object",
                                   NSUnderlyingErrorKey:e}];

        completion([OCSPCacheLookupResult lookupResultWithResponse:nil
                                                             error:error
                                                            cached:FALSE]);
        return;
    }

    [self lookup:leaf
      withIssuer:issuer
      andTimeout:timeout
   modifyOCSPURL:modifyOCSPURL
         session:session
      completion:completion];
}

/// See comment in header
- (OCSPCacheLookupResult*)lookup:(SecTrustRef)secTrustRef
                      andTimeout:(NSTimeInterval)timeout
                   modifyOCSPURL:(NSURL* (^__nullable)(NSURL *url))modifyOCSPURL
                         session:(NSURLSession*__nullable)session
{
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    __block OCSPCacheLookupResult* r;

    [self lookup:secTrustRef
      andTimeout:timeout
   modifyOCSPURL:modifyOCSPURL
         session:session
      completion:^(OCSPCacheLookupResult * _Nonnull result) {
          r = result;
        dispatch_semaphore_signal(sem);
      }];

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER); // There is a timeout in the lookup call

    return r;
}

/// See comment in header
- (NSArray<OCSPCacheLookupResult*>*)lookupAll:(SecTrustRef)secTrustRef
                                   andTimeout:(NSTimeInterval)timeout
                                modifyOCSPURL:(NSURL* (^__nullable)(NSURL *url))modifyOCSPURL
                                      session:(NSURLSession*__nullable)session
{

    CFIndex certCount = SecTrustGetCertificateCount(secTrustRef);

    dispatch_group_t group = dispatch_group_create();

    __block NSMutableArray<OCSPCacheLookupResult*>* results = [[NSMutableArray alloc] init];

    for (int i = 0; i < certCount-1; i++) {
        dispatch_group_enter(group);
    }

    for (int i = 0; i < certCount-1; i++) {
        SecCertificateRef issued = SecTrustGetCertificateAtIndex(secTrustRef, i);
        SecCertificateRef issuer = SecTrustGetCertificateAtIndex(secTrustRef, i+1);

        [self lookup:issued
          withIssuer:issuer
          andTimeout:timeout
       modifyOCSPURL:modifyOCSPURL
             session:session
          completion:^(OCSPCacheLookupResult * _Nonnull result) {
              @synchronized (results) {
                  [results addObject:result];
              }
              dispatch_group_leave(group);
          }];
    }

    dispatch_group_wait(group, DISPATCH_TIME_FOREVER); // There is a timeout in the lookup call

    return results;
}


// See comment in header
- (void)lookup:(SecCertificateRef)secCertRef
    withIssuer:(SecCertificateRef)issuerRef
    andTimeout:(NSTimeInterval)timeout
 modifyOCSPURL:(NSURL* (^__nullable)(NSURL *url))modifyOCSPURL
       session:(NSURLSession*__nullable)session
    completion:(void (^)(OCSPCacheLookupResult *result))completion {

    __weak OCSPCache *weakSelf = self;

    dispatch_async(workQueue, ^{

        __strong OCSPCache *strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }

        NSString *key = [OCSPCache sha256Base64Key:secCertRef];

        // TODO: It could be worth replacing RACReplaySubject with something more lightweight
        //       like promises: https://github.com/google/promises
        RACReplaySubject<OCSPResponse*>* response;

        @synchronized (self) {
            NSData *cachedResponse = [strongSelf->cache objectForKey:key];
            if (cachedResponse) {
                OCSPResponse *r = [[OCSPResponse alloc] initWithData:cachedResponse];
                if (r != nil) {
                    [self log:@"Cache returned response"];
                    dispatch_async(strongSelf->callbackQueue, ^{
                        completion([OCSPCacheLookupResult lookupResultWithResponse:r
                                                                             error:nil
                                                                            cached:TRUE]);
                    });
                    return;
                } else {
                    [self log:@"Error: cache returned invalid data, evicting invalid data"];
                    [self removeCacheValueForKey:key];
                }
            }

            RACReplaySubject<OCSPResponse*>* cachedPendingResponse =
            [self->pendingResponseCache objectForKey:key];

            // Check if a response is already being fetched
            if (cachedPendingResponse != nil) {
                [self log:@"Cache returned pending response"];

                [[cachedPendingResponse subscribeOn:strongSelf->scheduler]
                 subscribeNext:^(OCSPResponse * _Nullable x) {
                     [self log:@"Pending response from cache got result"];
                     dispatch_async(strongSelf->callbackQueue, ^{
                         completion([OCSPCacheLookupResult lookupResultWithResponse:x
                                                                              error:nil
                                                                             cached:TRUE]);
                     });
                 } error:^(NSError * _Nullable error) {
                     [self logError:error];
                     dispatch_async(strongSelf->callbackQueue, ^{
                         completion([OCSPCacheLookupResult lookupResultWithResponse:nil
                                                                              error:error
                                                                             cached:FALSE]);
                     });
                 } completed:^{
                     [self log:@"Pending response completed"];
                 }];
                return;
            }

            // No response is currently being fetched, put pending response in the cache

            response = [RACReplaySubject replaySubjectWithCapacity:1];
            [self->pendingResponseCache setObject:response forKey:key];
        }

        // Get the OCSP request URLs
        // NOTE:
        // OCSPURL:ocspURLsFromSecCertRef:withIssuerCertRef:error:
        // will return an error if there are 0 OCSP URLs in the certificate, so we do not
        // need to double check.
        NSError *errorGettingOCSPURLs;
        NSArray<NSURL*>* urls = [OCSPCert ocspURLsFromSecCertRef:secCertRef
                                                           error:&errorGettingOCSPURLs];
        if (errorGettingOCSPURLs != nil) {
            NSError *err =
            [NSError errorWithDomain:OCSPCacheErrorDomain
                                code:OCSPCacheErrorConstructingOCSPRequests
                            userInfo:@{NSLocalizedDescriptionKey:@"Error constructing OCSP "
                                                                  "requests",
                                       NSUnderlyingErrorKey:errorGettingOCSPURLs}];
            [self logError:err];
            @synchronized (self) {
                [self->pendingResponseCache removeObjectForKey:key];
            }
            [response sendError:err];
            dispatch_async(strongSelf->callbackQueue, ^{
                completion([OCSPCacheLookupResult lookupResultWithResponse:nil
                                                                     error:err
                                                                    cached:FALSE]);
            });
            return;
        }

        // Get data required for OCSP request with the POST method

        NSError *errorGettingOCSPRequestData;
        NSData *ocspReqData = [OCSPCert ocspDataForPostRequestFromSecCertRef:secCertRef
                                                           withIssuerCertRef:issuerRef
                                                                       error:&errorGettingOCSPURLs];

        if (errorGettingOCSPRequestData != nil) {
            NSError *err =
            [NSError errorWithDomain:OCSPCacheErrorDomain
                                code:OCSPCacheErrorConstructingOCSPRequests
                            userInfo:@{NSLocalizedDescriptionKey:@"Error constructing OCSP "
                                                                  "requests",
                                       NSUnderlyingErrorKey:errorGettingOCSPURLs}];
            [self logError:err];
            @synchronized (self) {
                [self->pendingResponseCache removeObjectForKey:key];
            }
            [response sendError:err];
            dispatch_async(strongSelf->callbackQueue, ^{
                completion([OCSPCacheLookupResult lookupResultWithResponse:nil
                                                                     error:err
                                                                    cached:FALSE]);
            });
            return;
        }

        // Check if the URLs need to be modified

        NSMutableArray<NSURL*>* newURLs = [[NSMutableArray alloc] initWithArray:urls];

        if (modifyOCSPURL) {
            for (int i = 0; i < [urls count]; i++) {
                NSURL *oldURL = [urls objectAtIndex:i];
                NSURL *newURL = modifyOCSPURL(oldURL);
                if (newURL != nil) {
                    [newURLs setObject:newURL atIndexedSubscript:i];
                }
            }
        }

        // Make OCSP requests

        [[OCSPRequestService getSuccessfulOCSPResponse:newURLs
                                       ocspRequestData:ocspReqData
                                               session:session
                                                 queue:strongSelf->workQueue]
         subscribeNext:^(NSObject * _Nullable x) {
             // OCSPService emits NSError and OCSPResponse
             // - Each error encountered is emitted
             // - Each OCSP response obtained is emitted
             // - If no successful response can be retrieved, an error is returned
             if ([x isKindOfClass:[NSError class]]) {
                 // Network error from OCSPService
                 NSError *e = (NSError*)x;
                 [self log:[NSString stringWithFormat:@"%@", e]];
             } else if ([x isKindOfClass:[OCSPResponse class]]) {
                 // OCSP response from OCSPService
                 // Still need to check if it was successful
                 OCSPResponse *r = (OCSPResponse*)x;
                 if (r.success) {
                     // Successful response, OCSPServer will complete after emitting this
                     [response sendNext:r];
                     [response sendCompleted];
                 } else {
                     [self log:[NSString stringWithFormat:@"Got invalid OCSP response with code: "
                                                           "%d", [r status]]];
                 }
             } else {
                 // Should never happen
                 [response sendError:[OCSPCache unknownObjectError:x]];
             }
         } error:^(NSError * _Nullable error) {
             NSError *err =
             [NSError errorWithDomain:OCSPCacheErrorDomain
                                 code:OCSPCacheErrorCodeNoSuccessfulResponse
                             userInfo:@{NSLocalizedDescriptionKey:
                                        @"Failed to get a succesful response"}];
             [response sendError:err];
         } completed:^{
             [self log:@"OCSPService completed"];
         }];

        // Wait for response with timeout

        NSError *timeoutError =
        [NSError errorWithDomain:OCSPCacheErrorDomain
                            code:OCSPCacheErrorCodeLookupTimedOut
                        userInfo:@{NSLocalizedDescriptionKey:@"Lookup timed out"}];

        RACSignal *responseWithOptionalTimeout;

        if (timeout > 0) {
            responseWithOptionalTimeout =
            [[response merge:[[RACSignal return:timeoutError] delay:timeout]] take:1];
        } else {
            responseWithOptionalTimeout = response;
        }

        [[[responseWithOptionalTimeout subscribeOn:strongSelf->scheduler]
         flattenMap:^__kindof RACSignal * _Nullable(id  _Nullable x) {

            if ([x isKindOfClass:[NSError class]]) {
                return [RACSignal error:x];
            } else if ([x isKindOfClass:[OCSPResponse class]]) {
                return [RACSignal return:x];
            }

            return [RACSignal error:[OCSPCache unknownObjectError:x]];
        }] subscribeNext:^(OCSPResponse *r) {
            @synchronized (self) {
                // Add response to the cache and remove pending response
                [strongSelf->cache setObject:r.data forKey:key];
                [strongSelf->pendingResponseCache removeObjectForKey:key];
            }
            dispatch_async(strongSelf->callbackQueue, ^{
                completion([OCSPCacheLookupResult lookupResultWithResponse:r
                                                                     error:nil
                                                                    cached:FALSE]);
            });
            [self log:@"Service returned response"];

         } error:^(NSError * _Nullable err) {
             @synchronized (self) {
                 [self->pendingResponseCache removeObjectForKey:key];
             }
             [self logError:err];
             dispatch_async(strongSelf->callbackQueue, ^{
                 completion([OCSPCacheLookupResult lookupResultWithResponse:nil
                                                                      error:err
                                                                     cached:FALSE]);
             });
        } completed:^{
            // Should never happen
            [self log:@"Response completed"];
        }];
    });
}

/// See comment in header
- (OCSPCacheLookupResult*)lookup:(SecCertificateRef)secCertRef
                      withIssuer:(SecCertificateRef)issuerRef
                      andTimeout:(NSTimeInterval)timeout
                   modifyOCSPURL:(NSURL* (^__nullable)(NSURL *url))modifyOCSPURL
                         session:(NSURLSession*__nullable)session
{
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    __block OCSPCacheLookupResult* r;

    [self lookup:secCertRef
      withIssuer:issuerRef
      andTimeout:timeout
   modifyOCSPURL:modifyOCSPURL
         session:session
      completion:^(OCSPCacheLookupResult * _Nonnull result) {
          r = result;
          dispatch_semaphore_signal(sem);
      }];

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER); // There is a timeout in the lookup call

    return r;
}

#pragma mark - Managing the cache

// See comment in header
- (void)setCacheValueForCert:(SecCertificateRef)secCertRef data:(nonnull NSData *)data {
    NSString *key = [OCSPCache sha256Base64Key:secCertRef];

    @synchronized (self) {
        [cache setObject:data forKey:key];
    }
}

// See comment in header
- (BOOL)removeCacheValueForCert:(SecCertificateRef)secCertRef {
    NSString *key = [OCSPCache sha256Base64Key:secCertRef];

    return [self removeCacheValueForKey:key];
}

// See comment in header
- (BOOL)removeCacheValueForKey:(NSString*)key {
    BOOL valueEvicted = NO;

    [self log:@"Evicting cache value"];
    @synchronized (self) {
        if ([cache objectForKey:key]) {
            [cache removeObjectForKey:key];
            valueEvicted = TRUE;
        }
    }

    [self log:@"Evicted cache value"];
    return valueEvicted;
}

#pragma mark - Certificate hashing

// TODO: there could be a more concise key
+ (NSString*)sha256Base64Key:(SecCertificateRef)secCertRef {
    NSData *dataIn = (__bridge_transfer NSData *)SecCertificateCopyData(secCertRef);

    NSMutableData *macOut = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(dataIn.bytes, (unsigned int)dataIn.length, macOut.mutableBytes);

    return [macOut base64EncodedStringWithOptions:0];
}

#pragma mark - Logging

- (void)logError:(NSError*)error {
    [self log:[NSString stringWithFormat:@"%@", error]];
}

- (void)log:(NSString*)log {
    __weak OCSPCache *weakSelf = self;

    dispatch_async(logQueue, ^{
        __strong OCSPCache *strongSelf = weakSelf;
        if (!strongSelf) {
            return;
        }
        if (strongSelf->logger) {
            self->logger(log);
        }
    });
}

#pragma mark - Errors

+ (NSError*)unknownObjectError:(NSObject*)x {
    NSString *localizedDescription =
    [NSString stringWithFormat:@"Unexpected response of class %@",
     NSStringFromClass([x class])];

    NSError *e =
    [NSError errorWithDomain:OCSPCacheErrorDomain
                        code:OCSPCacheErrorCodeUnknown
                    userInfo:@{NSLocalizedDescriptionKey:localizedDescription}];

    return e;
}

@end
