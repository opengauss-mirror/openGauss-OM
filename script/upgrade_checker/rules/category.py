#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#############################################################################
# Copyright (c) 2023 Huawei Technologies Co.,Ltd.
#
# openGauss is licensed under Mulan PSL v2.
# You can use this software according to the terms
# and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS,
# WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# ----------------------------------------------------------------------------
# Description  : gs_upgradechk is a utility to check meta data in gaussdb after upgrade.
#############################################################################

from enum import Enum

class Category(Enum):
    """
    聚类，用于对系统表进行分类和报告的输出。
    值的大小目前并没有什么实际意义，但修改时仍需要升级工具。
    """
    UNKNOWN = 0             # 未知
    DATABASE = 1            # 数据库
    TABLESPACE = 2          # 表空间
    SCHEMA = 3              # 模式、名称空间
    TABLE = 4               # 表
    VIEW = 5                # 视图
    INDEX = 6               # 索引
    FUNCTION = 7            # 函数、存储过程
    TYPE = 8                # 数据类型
    OPERATOR = 9            # 操作符
    TRIGGER = 10            # 触发器
    SEQUENCE = 11           # 序列
    CONSTRAINT = 12         # 约束
    AM = 13                 # 访问方法 access method
    LANGUAGE = 14           # 语言
    PACKAGE = 15            # 包
    RULE = 16               # 规则
    LOCALE = 17             # 编码、排序等
    DIRECTORY = 18          # 文件夹
    SYNONYM = 19            # 同义词
    DESCRIPTION = 20        # 注释
    EXTENSION = 21          # 插件扩展
    FDW = 22                # 外部数据包装器
    TS = 23                 # 文本分词搜索
    RECYCLE_BIN = 24        # 回收站
    PUB_SUB = 25            # 发布订阅
    OPTIMIZER = 26          # 优化器
    TRANSACTION = 27        # 事务
    REPLICATION = 28        # 流复制
    INFO_SCHEMA = 29        # information schema
    PLDEV_SCHEMA = 30       # pl_developer schema
    AI = 31                 # AI
    DEPEND = 32             # 依赖关系
    GUC = 33                # guc 配置
    JOB = 34                # 定时任务
    OBS = 35                # 对象存储
    LOB = 36                # 大对象
    OBJECT = 37             # 用户数据库对象
    AUTHENTICATION = 38     # 认证
    PRIVILEGE = 39          # 权限
    SECURITY = 40           # 安全
    WLM = 41                # workload manager 资源管理
    DFX = 42                # Design For X
    WDR = 43                # wdr报告
    DISTRIBUTE = 44         # 分布式
    
    
