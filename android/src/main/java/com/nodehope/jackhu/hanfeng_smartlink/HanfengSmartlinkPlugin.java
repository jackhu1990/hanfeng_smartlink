package com.nodehope.jackhu.hanfeng_smartlink;

import com.hiflying.smartlink.ISmartLinker;
import com.hiflying.smartlink.OnSmartLinkListener;
import com.hiflying.smartlink.SmartLinkedModule;
import com.hiflying.smartlink.v7.MulticastSmartLinker;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;

/** HanfengSmartlinkPlugin */
public class HanfengSmartlinkPlugin implements MethodCallHandler {
  private final Registrar mRegistrar;

  // 使用构造函数缓存flutter register, register 可以获得android上下文
  public HanfengSmartlinkPlugin(Registrar mRegistrar) {
    this.mRegistrar = mRegistrar;
  }

  /** Plugin registration. */
  public static void registerWith(Registrar registrar) {
    final MethodChannel channel = new MethodChannel(registrar.messenger(), "hanfeng_smartlink");
    channel.setMethodCallHandler(new HanfengSmartlinkPlugin(registrar));
  }

  protected ISmartLinker mSmartLinker;

  @Override
  public void onMethodCall(MethodCall call, final Result result) {
    if (call.method.equals("getPlatformVersion")) {
      result.success("Android " + android.os.Build.VERSION.RELEASE);
    } else if (call.method.equals("startLink")) {
      final String ssid = call.argument("ssid");
      final String password = call.argument("password");
      try {
        mSmartLinker = MulticastSmartLinker.getInstance();
        mSmartLinker.setOnSmartLinkListener(new OnSmartLinkListener(){
          @Override
          public void onLinked(final SmartLinkedModule module) {
            result.success(module.getMac());
          }
          @Override
          public void onCompleted() {
          }
          @Override
          public void onTimeOut() {
            result.error("TIMEOUT","超时,未成功,请检查wifi帐号密码是否正确", null);
          }
        });
        //开始 smartLink
        mSmartLinker.start(mRegistrar.context(), password.trim(), ssid.trim());
      } catch (Exception e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
        result.error("SDKERROR","连接wifi时出现异常", null);
      }

    }else {
      result.notImplemented();
    }
  }
}
