Pod::Spec.new do |s|
  s.name             = 'OCSPCache'
  s.version          = '0.1.1'
  s.summary          = 'OCSPCache is used for making OCSP requests and caching OCSP responses.'
  s.homepage         = 'https://psiphon3.com'
  s.license          = { :type => 'GNU General Public License v3.0' }
  s.platform          = :ios
  s.author           = { 'Psiphon Inc' => 'info@psiphon.ca' }
  s.source           = { :git => 'https://github.com/Psiphon-Labs/OCSPCache.git', :tag => s.version.to_s }

  s.ios.deployment_target = '8.0'
  s.source_files = 'OCSPCache/Classes/**/*'
  s.dependency 'ReactiveObjC', '3.1.1' 
  s.dependency 'OpenSSL-Universal', '1.0.2.17'
  s.pod_target_xcconfig = { 'VALID_ARCHS' => 'arm64 armv7 x86_64' }
end
