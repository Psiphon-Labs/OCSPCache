#!/bin/bash

xcodebuild test -workspace OCSPCache.xcworkspace -scheme OCSPCache-Example -destination 'platform=iOS Simulator,name=iPhone 5s,OS=12.4'

