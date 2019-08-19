#import "HanfengSmartlinkPlugin.h"

#import "SmartLinkLib/HFSmartLink.h"

@implementation HanfengSmartlinkPlugin
{
  HFSmartLink * smtlk;
}
+ (void)registerWithRegistrar:(NSObject<FlutterPluginRegistrar>*)registrar {
  FlutterMethodChannel* channel = [FlutterMethodChannel
      methodChannelWithName:@"hanfeng_smartlink"
            binaryMessenger:[registrar messenger]];
  HanfengSmartlinkPlugin* instance = [[HanfengSmartlinkPlugin alloc] init];
  [registrar addMethodCallDelegate:instance channel:channel];
}

- (void)handleMethodCall:(FlutterMethodCall*)call result:(FlutterResult)result {
  if ([@"getPlatformVersion" isEqualToString:call.method]) {
    result([@"iOS " stringByAppendingString:[[UIDevice currentDevice] systemVersion]]);
  }
  else if ([@"startLink" isEqualToString:call.method]) {
    NSString *ssid = call.arguments[@"ssid"];
    NSString *password = call.arguments[@"password"];
    smtlk = [HFSmartLink shareInstence];
    [smtlk startWithSSID:ssid Key:password UserStr:@"" withV3x:false
        processblock: ^(NSInteger pro) {

        } successBlock:^(HFSmartLinkDeviceInfo *dev) {
            result([NSString stringWithFormat:@"%@",dev.mac]);
        } failBlock:^(NSString *failmsg) {
            result([FlutterError
                      errorWithCode:@"TIMEOUT"
                            message:@"连接wifi时出现异常"
                            details:nil]);
        } endBlock:^(NSDictionary *deviceDic) {
            result([FlutterError
                      errorWithCode:@"SDKERROR"
                            message:@"超时,未成功,请检查wifi帐号密码是否正确"
                            details:nil]);
        }];
  }
  else {
    result(FlutterMethodNotImplemented);
  }
}

@end
