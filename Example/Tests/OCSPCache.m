//
//  OCSPCache.m
//  OCSPCache
//
/*
 Licensed under Creative Commons Zero (CC0).
 https://creativecommons.org/publicdomain/zero/1.0/
 */

#import "OCSPCache.h"
#import <CommonCrypto/CommonDigest.h>
#import <openssl/ocsp.h>
#import "OCSP.h"
#import "RACReplaySubject.h"

@implementation OCSPCache {
    NSMutableDictionary<NSData*, RACReplaySubject<OCSPResponse *>*>* cache;
    void (^logger)(NSString*);
    dispatch_queue_t workQueue;
}

- (instancetype)init {
    self = [super init];

    if (self) {
        [self initTasks];
    }

    return self;
}

- (instancetype)initWithLogger:(void (^)(NSString * _Nonnull log))logger {
    self = [super init];

    if (self) {
        [self initTasks];
        self->logger = logger;

    }

    return self;
}

- (void)initTasks {
    cache = [[NSMutableDictionary alloc] init];
    workQueue = dispatch_queue_create("ca.psiphon.OCSPCache.WorkQueue", DISPATCH_QUEUE_CONCURRENT);
}

// TODO: this signature could be more concise; we only need the issuer to construct the OCSP
//       request
//
// TODO: use POST method for OCSP requests (look into benefits – firefox switched over)
//
- (void)lookup:(SecCertificateRef)secCertRef
                                  withIssuer:(SecCertificateRef)issuerRef
                              andCompletion:(void (^__nonnull)(OCSPResponse *response, BOOL cached))completion {

    NSError *e;
    NSArray<NSURL*>* ocspURLs = [OCSP ocspURLsFromSecCertRef:secCertRef
                                           withIssuerCertRef:issuerRef
                                                       error:&e];
    if (e != nil) {
        NSLog(@"Error constructing OCSP requests: %@", e.localizedDescription);
        // TODO: error handling
        return;
    }

    if ([ocspURLs count] == 0) {
        NSLog(@"Error no OCSP URLs in the Certificate Authority Information Access "
              "(1.3.6.1.5.5.7.1.1) extension.");
        // TODO: error handling
        return;
    }

    // Calculate SHA256 hash
    // TODO: factor out
    NSData *dataIn = (__bridge_transfer NSData *)SecCertificateCopyData(secCertRef);

    NSMutableData *macOut = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(dataIn.bytes, (unsigned int)dataIn.length,  macOut.mutableBytes);

    RACReplaySubject *response = [RACReplaySubject replaySubjectWithCapacity:1];

    @synchronized (self) {
        // TODO: need to check if,
        //       - response is expired
        //       - SecTrustEvaluate rejects the response

        RACReplaySubject<OCSPResponse*>* cachedResponse = [cache objectForKey:macOut];

        if (cachedResponse != NULL) {
            [cachedResponse subscribeNext:^(OCSPResponse * _Nullable x) {
                completion(x, TRUE);
            }];
            return;
        }


        [cache setObject:response forKey:macOut];
    }

    dispatch_async(workQueue , ^{
        for (NSURL *ocspURL in ocspURLs) {
            NSURLResponse *resp = nil;
            NSError *e = nil;

            NSURLRequest *ocspReq = [NSURLRequest requestWithURL:ocspURL];

            NSData *data = [NSURLConnection sendSynchronousRequest:ocspReq
                                                 returningResponse:&resp
                                                             error:&e];

            if (e != nil) {
                NSLog(@"Error with OCSP request: %@", e.localizedDescription);
                // TODO: send error
                continue;
            }

            [response sendNext:data];
            [response sendCompleted];

            break;
        }
    });

    [response subscribeNext:^(id  _Nullable x) {
        completion(x, FALSE);
    }];
}

- (void)log:(NSString*)log {
    if (logger) {
        logger(log);
    }
}

@end
