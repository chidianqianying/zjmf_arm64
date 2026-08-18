# 开心魔方拓展

移植到ARM64的适配插件

### 魔方财务系统使用方法

_魔方财务系统支持版本： **=3.7.6**_

1. 首先需要安装php扩展。根据网站要使用的php版本，下载扩展文件（[php7.2](https://github.com/你的用户名/你的仓库/raw/main/ext/php7.2/idcsmart.so)、[php7.3](https://github.com/你的用户名/你的仓库/raw/main/ext/php7.3/idcsmart.so)、[php7.4](https://github.com/你的用户名/你的仓库/raw/main/ext/php7.4/idcsmart.so)），上传到php安装目录 /lib/php/extensions/no-debug-non-zts-xxxx（xxxx为一串数字）文件夹里面。

2. 修改php配置文件（php.ini），加入以下内容，然后重启php进程。

   ```
   extension=idcsmart.so
   ```

3. 使用[官方安装包](https://github.com/aazooo/zjmf)进行安装。填写授权码的时候，随便填写一个的32位大写的MD5字符串，例如可以[在这里生成](https://md5jiami.bmcx.com/)。（之前用过官方安装包的，还需要解压此安装包单独覆盖vendor目录）
   该官方安装包已经集成部分常用插件，无需再去商店购买。

4. 安装完之后默认就是专业版，所有专业版的功能均可使用。

5. 如果上传了第三方付费插件或模板，使用过程中提示插件未购买，需要在php配置文件（php.ini）加入idcsmart.app这个配置项，配置第三方插件标识，多个插件标识用英文逗号隔开，例如：

   ```
   idcsmart.app=AliPayDmf,Smsbao,Subemail
   ```

   重启php进程，在后台系统升级页面，已授权模块处，点击"拉取授权"。即可使用付费的第三方插件或模板。

---

> **原仓库地址：** https://github.com/aazooo/zjmf
>
> **声明：** 官方安装包和本适配插件于 **2026年8月18日** 有效，并不保证跟随原仓库更新。本项目处于开发版本，有可能存在未知bug，请谨慎使用。
