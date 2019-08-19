import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hanfeng_smartlink/hanfeng_smartlink.dart';

void main() {
  const MethodChannel channel = MethodChannel('hanfeng_smartlink');

  setUp(() {
    channel.setMockMethodCallHandler((MethodCall methodCall) async {
      return '42';
    });
  });

  tearDown(() {
    channel.setMockMethodCallHandler(null);
  });

  test('getPlatformVersion', () async {
    expect(await HanfengSmartlink.platformVersion, '42');
  });
}
