# openGauss-OM

#### 介绍

运维管理模块(OperationManager)提供openGauss日常运维、配置管理的管理接口和工具

#### 编译出包

- 参考opengauss的[三方库说明](https://gitee.com/opengauss/openGauss-server#%E7%BC%96%E8%AF%91%E7%AC%AC%E4%B8%89%E6%96%B9%E8%BD%AF%E4%BB%B6)，准备好编译完的三方库，     
  目录名记为 ${BINARYLIBS_PATH} 。      
  提供编译好的三方库二进制可以直接下载使用： [openGauss-third_party_binarylibs.tar.gz](https://opengauss.obs.cn-south-1.myhuaweicloud.com/2.0.0/openGauss-third_party_binarylibs.tar.gz)
- ./build.sh -3rd ${BINARYLIBS_PATH}       
  命令执行成功后，生成的包在package目录下：      
  openGauss-2.0.0-CentOS-64bit-om.sha256      
  openGauss-2.0.0-CentOS-64bit-om.tar.gz       


#### 安装教程

OM工具强依赖opengaussServer，安装教程参考[opengauss安装指南](https://opengauss.org/zh/docs/latest/docs/installation/installation.html)。

## 快速入门

参考[快速入门](https://opengauss.org/zh/docs/2.0.0/docs/Quickstart/Quickstart.html)。

## 文档

更多安装指南、教程和API请参考[用户文档](https://gitee.com/opengauss/docs)。

## 社区

### 治理

查看openGauss是如何实现开放[治理](https://gitee.com/opengauss/community/blob/master/governance.md)。

### 交流

- WeLink：开发者的交流平台。
- IRC频道：`#opengauss-meeting`（仅用于会议纪要）。
- 邮件列表：https://opengauss.org/zh/community/onlineCommunication.html

## 贡献

欢迎大家来参与贡献。详情请参阅我们的[社区贡献](https://opengauss.org/zh/contribution.html)。

## 发行说明

请参见[发行说明](https://opengauss.org/zh/docs/2.0.0/docs/Releasenotes/Releasenotes.html)。

## 许可证

[MulanPSL-2.0](http://license.coscl.org.cn/MulanPSL2/)
