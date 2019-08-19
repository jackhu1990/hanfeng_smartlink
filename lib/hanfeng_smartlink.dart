import 'dart:async';

import 'package:flutter/services.dart';
import 'package:connectivity/connectivity.dart';

class HanfengSmartlink {
  static const MethodChannel _channel = const MethodChannel('hanfeng_smartlink');

  static Future<String> get platformVersion async {
    final String version = await _channel.invokeMethod('getPlatformVersion');
    return version;
  }

  static Future<String> get getWifiName async {
    var wifiName = await (Connectivity().getWifiName());
    return wifiName;
  }

  static Future<bool> get isWifi async{
    var connectivityResult = await (Connectivity().checkConnectivity());
    if (connectivityResult == ConnectivityResult.wifi) {
      return true;
    } else{
      return false;
    }
  }

  static Future<bool> startLink(String ssid, String password) async {
    return await _channel.invokeMethod<bool>(
      'startLink',
      <String, Object>{'ssid': ssid, 'password': password},
    );
  }

}
