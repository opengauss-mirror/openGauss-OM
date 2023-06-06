[TOC]

# 开发者工具脚本
## StandardVmapGen

## OGController

## FastCheck



# 工具升级指导

## 什么时候工具要升级
首先我们需要明确如下几点：
1、工具的核心数据是一批规则，规则的中心是SQL
2、VMAP的本质是工具内的SQL及其查询结果
3、工具将自身SQL在数据库内进行查询，并将查询结果与VMAP内预期结果进行对比。

而当工具内的规则发生变化，便需要升级工具，并生成对应的VMAP。


一些典型的场景如下：
- openGauss元数据发生变化，导致工具内有些规则内的SQL执行报错，或者不再合理时
- 工具内的

需要注意的是，单纯的openGauss元数据变化，并不代表需要升级工具。


## 怎么去给工具做升级
1、按照自己的需求，修改工具内的校验规则。

2、将version.py中UPGRADE_CHECKER_VERSION进行修改加一。

3、下载version.py中FOR_OPENGAUSS所列出来的openGauss版本压缩包，进行测试。

4、为测试通过的版本使用`Dev/StandardVmapGen.py`来导出基准校验地图。

5、更新根目录下《README.MD》内版本支持列表

6、将新的基准校验地图上传至openGauss华为云obs存储位置。


# 适配openGauss新版本
当openGauss发布新版本时，并不代表着需要升级工具，但一定需要为新版openGauss生成一个新的VMAP。

首先我们需要安装运行一个openGauss新版本，并且下载本工具，之后按照如下步骤适配openGauss最新版：

1、使用当前工具，对openGauss新版本进行VMAP导出测试。
    - 修改version.py中的FOR_OPENGAUSS, 将新的openGauss版本添加到其中。
    - 使用工具导出新版本openGauss的VMAP。可正常导出，或用`Dev/StandardVmapGen.py`
    
2、修复导出测试过程中的告警、错误并重新测试导出，直到完美导出VMAP。

3、使用导出的vmap，对openGauss新版本进行check校验。

4、修复校验过程中的告警、错误，校验报告中的告警、错误，并从头重新测试，直到完美的完成校验报告。

5、检查上述过程中的修改是否涉及到工具升级。若涉及则需要升级工具。

6、使用新的VMAP进行openGauss老版本到当前新版本的升级测试。

6、将新的标准VMAP(还有工具升级涉及生成的新的)，上传到openGauss华为云obs存储位置。
