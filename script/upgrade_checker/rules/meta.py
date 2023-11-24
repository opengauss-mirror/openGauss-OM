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

"""
校验规则的元数据，根据这些数据、结构，生成校验规则。
"""

from enum import Enum
from upgrade_checker.rules.category import Category


class Accuracy(Enum):
    STRICT = 0        # 严格精确
    ALLOW_MORE = 1    # 查询允许多数据，对于完全无法区分是用户数据还是内建数据的检验sql，我们只能够通过允许多数据来解决。
    ALLOW_LACK = 2    # 查询允许少数据，用于在系统表不稳定存在时，可以允许缺少这些查询数据。


class Meta(object):
    def __init__(self, category=Category.UNKNOWN, desc="", certain=True, content_meta=None):
        self.category = category
        self.desc = desc
        self.certain = certain
        self.content_rules_meta = content_meta if content_meta is not None else []


class ContentRulesMeta(object):
    def __init__(self, key=None, filters=None, ignore_col=None, oid_col=None,
                 complete_sql=None, complete_sql_desc=None,
                 key_desc="内容哈希值为%s的行", accuracy=Accuracy.STRICT):
        """
        用来生成校验一个表的内容的信息。这些入参有两种使用方式，
        1、可以使用第一行的几个入参，拼凑出来一句完成的SQL语句
        2、在第二行的入参中，如果提供了完整的SQL，则不再去进行拼接。
        第三行的入参为前两中方式共用的。
        建议尽可能使用第一种方式，因为这样的话当表结构发生变化时，会具有一定的自适应能力。

        :param key: sql的键，必须是明确的一个投影，None表示用所有需要校验的列进行字符串连接做投影。
        :param filters: where过滤条件，用与区分用户数据和builtin数据。None表示不过滤
        :param ignore_col: 需要忽略的列。None表示使用所有列。
        :param oid_col: 需要校验的列中，类型为oid的需要特殊处理列。特殊处理的话，这些会被0-9999，1W-16383的区分处理，1W以上安0。None表示没有
        :param complete_sql: 完整的SQL规则，如果提供这个选项，则不会再用前面的拼接参数去拼接组装。
        :param complete_sql_desc: 完整的SQL描述。
        :param key_desc: sql的键的描述，注意必现带一个%s
        :param accuracy: 校验精度, 默认严格
        """
        self.key = key
        self.key_desc = key_desc
        self.filters = filters if filters is not None else 'true'
        self.ignore_col = ignore_col.split(',') if ignore_col is not None else []
        self.oid_col = oid_col.split(',') if oid_col is not None else []
        self.complete_sql = complete_sql
        self.complete_sql_desc = complete_sql_desc
        self.accuracy = accuracy


META = {
    'default.default': Meta(
        Category.UNKNOWN,
        '未知系统表',
        True,
        [
            ContentRulesMeta()
        ]
    ),
    'pg_catalog.pg_default_acl': Meta(
        Category.AUTHENTICATION,
        '存储新建对象设置的初始权限',
        True
    ),
    'pg_catalog.pg_pltemplate': Meta(
        Category.FUNCTION,
        '存储过程语言的"模板"信息',
        True,
        [
            ContentRulesMeta(
                key='tmplname',
                key_desc='名称为%s的模板',
                ignore_col='tmplacl'
            )
        ]
    ),
    'pg_catalog.pg_tablespace': Meta(
        Category.TABLESPACE,
        '所有表空间的信息',
        True,
        [
            ContentRulesMeta(
                key='spcname',
                key_desc='名称为%s的表空间',
                filters=' oid < 10000 ',
                ignore_col='spcacl'
            )
        ]
    ),
    'pg_catalog.pg_shdepend': Meta(
        Category.DEPEND,
        '记录数据库对象和共享对象之间的依赖性关系',
        True
        # 暂时不进行校验，原因同 pg_depend
    ),
    'pg_catalog.pg_type': Meta(
        Category.TYPE,
        '记录所有的数据类型信息',
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的数据类型',
                filters=' oid < 10000 ',
                ignore_col='tydefaultbin,typacl',
                oid_col='typnamespace,typrelid,typelem'
            ),
            ContentRulesMeta(
                key="(select nspname from pg_namespace n where n.oid = typnamespace) || '.' || typname",
                key_desc='数据类型%s',
                filters=' oid < 10000 ',
                ignore_col='oid,tydefaultbin,typacl',
                oid_col='typnamespace,typowner,typrelid,typelem,typarray,typbasetype,typcollation'
            )
        ]
    ),
    'pg_catalog.pg_attribute': Meta(
        Category.TABLE,
        "存储了所有表、视图的所有列的基础信息",
        True,
        [
            # builtin的需要严格一致
            ContentRulesMeta(
                key="format('%s(%s)',"
                    " (select format('%s.%s', nspname, relname)"
                    "  from pg_class c left join pg_namespace n on c.relnamespace = n.oid "
                    "  where c.oid=attrelid),"
                    " attname"
                    ")",
                key_desc='模式.关系名(列名)为%s的列',
                filters=' attrelid < 10000 ',
                ignore_col='attacl'
            ),
            # initdb的。但忽略toast表，因为表名里也带oid，会变，无法校验。
            ContentRulesMeta(
                complete_sql="select format('%s.%s(%s)', n.nspname, c.relname, a.attname),"
                             "       md5(format('%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s', "
                             "                  t.typname, a.attstattarget, a.attlen, a.attnum, a.attndims,"
                             "                  a.attcacheoff, a.atttypmod, a.attbyval, a.attstorage, a.attalign,"
                             "                  a.attnotnull, a.atthasdef,a.attisdropped, a.attislocal, a.attcmprmode,"
                             "                  a.attinhcount, a.attcollation, a.attoptions, a.attfdwoptions,"
                             "                  a.attinitdefval, a.attkvtype))"
                             "from pg_attribute a left join pg_class c on a.attrelid = c.oid " 
                             "                    left join pg_namespace n on c.relnamespace = n.oid "
                             "                    left join pg_type t on a.atttypid = t.oid "
                             "where a.attrelid > 9999 and " 
                             "      a.attrelid < 16384 and " 
                             "      a.attisdropped = false and " 
                             "      n.nspname not in ('pg_toast')",
                key_desc='模式.关系名(列名)为%s的列',
                complete_sql_desc='校验initdb阶段(1W <= oid <= 16384)创建的表、索引、视图等的列信息。'
            )
        ]
    ),
    'pg_catalog.pg_proc': Meta(
        Category.FUNCTION,
        '存储了所有的函数、存储过程',
        True,
        [
            ContentRulesMeta(Category.FUNCTION,
                complete_sql = "select 'count(*)', count(*) from pg_proc where oid < 16384",
                key_desc = '数量统计方法%s',
                complete_sql_desc = 'pg_proc内 oid < 16384 的系统对象(包括函数、存储过程)总数量'
            ),
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的函数或存储过程',
                filters=' oid < 10000 ',
                ignore_col='proargdefaults,proacl'
            ),
            ContentRulesMeta(
                key="format('%s.%s(%s)',"
                    " (select nspname from pg_namespace n where n.oid = pronamespace),"
                    " proname,"
                    " pg_get_function_arguments(oid)"
                    ")",
                key_desc='函数%s',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid,proargtypes,proallargtypes,proargdefaults,proacl,proargtypesext,allargtypes,allargtypesext',
                oid_col='pronamespace,prolang,provariadic,prorettype,propackageid'
            ),
            ContentRulesMeta(
                complete_sql="select format('def:%s.%s(%s)', "
                             "              n.nspname, "
                             "              p.proname, "
                             "              pg_get_function_arguments(p.oid)), "
                             "       md5(pg_get_functiondef(p.oid)::text) "
                             "from pg_proc p left join pg_namespace n on p.pronamespace = n.oid "
                             "where p.oid < 16384 and p.proisagg=false and p.proiswindow=false",
                key_desc='函数%s的定义',
                complete_sql_desc='通过pg_get_functiondef()来检查一般函数的定义'
            )
        ]
    ),
    "pg_catalog.pg_class": Meta(
        Category.TABLE,
        '存储了所有表、索引、视图、序列等的基础信息。',
        True,
        [
            ContentRulesMeta(
                complete_sql="select 'count(*)', count(*) from pg_class where oid < 16384",
                key_desc='数量统计方法%s',
                complete_sql_desc='pg_class内oid < 16384(包括表、索引、视图、序列等)总数量'
            ),
            ContentRulesMeta(
                key="format('%s.%s',(select nspname from pg_namespace n where n.oid = relnamespace), relname)",
                key_desc='名为%s的表或索引或视图等',
                filters=' oid < 10000 ',
                ignore_col='relfilenode,relpages,reltuples,relallvisible,relacl,relfrozenxid,relfrozenxid64,relminmxid',
                oid_col='oid,reltype,reloftype',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="format('%s.%s',(select nspname from pg_namespace n where n.oid = relnamespace), relname)",
                key_desc='名为%s的表或索引或视图等',
                filters=" 9999 < oid and oid < 16384 and relnamespace not in (99) ",
                ignore_col='oid,relfilenode,relpages,reltuples,relallvisible,reltoastrelid,reltoastidxid,'
                           'relfrozenxid,relacl,relfrozenxid64,relminmxid',
                oid_col='relnamespace,reltype,reloftype,relowner,reltablespace',
                accuracy=Accuracy.STRICT
            ),
            # 表的会在第一步的校验系统表结构的时候校验pg_get_tabledef。
            # 索引等会在对应的扩展系统表校验，此处仅校验视图即可
            ContentRulesMeta(
                complete_sql="select format('def:%s.%s', n.nspname, c.relname), "
                             "       md5(pg_get_viewdef(c.oid)) "
                             "from pg_class c left join pg_namespace n on c.relnamespace=n.oid "
                             "where c.oid < 16384 and "
                             "      c.relkind in ('v') and "
                             "      n.nspname not in ('pg_toast', 'snapshot') ",
                key_desc='视图定义%s',
                complete_sql_desc='pg_get_viewdef()来检查视图的定义'
            )
        ]
    ),
    "pg_catalog.pg_authid": Meta(
        Category.AUTHENTICATION,
        "存储有关数据库认证标识符（角色）的信息",
        True,
        [
            ContentRulesMeta(
                key='oid',
                key_desc='oid为%s的角色',
                filters=' oid = 10 ',
                ignore_col='rolname,rolpassword,rolvalidbegin,rolvaliduntil,rolrespool,rolpasswordext'
            ),
            
            # 其余角色的各种属性理论都可以通过alter修改，无需校验
            ContentRulesMeta(
                complete_sql='select oid, rolname from pg_authid where oid < 10000 and oid != 10',
                key_desc='oid为%s的角色',
                complete_sql_desc='校验角色的信息'
            ),
            ContentRulesMeta(
                complete_sql='select rolname, rolname from pg_authid where 9999 < oid and oid < 16384',
                key_desc='角色%s',
                complete_sql_desc='校验角色的信息'
            )
        ]
    ),
    "pg_catalog.pg_auth_members": Meta(
        Category.AUTHENTICATION,
        "存储显示角色之间的成员关系",
        True,
        [
            ContentRulesMeta(
                filters=' roleid < 16384 '
            )
        ]
    ),
    "pg_catalog.pg_database": Meta(
        Category.DATABASE,
        "存储database信息",
        True,
        [
            ContentRulesMeta(
                key='datname',
                key_desc='数据库%s',
                filters=' oid < 10000 ',
                ignore_col='encoding,datcollate,datctype,datlastsysoid,datfrozenxid,datacl,datfrozenxid64,datminmxid'
            ),
            ContentRulesMeta(
                key='datname',
                key_desc='数据库%s',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid,encoding,datcollate,datctype,datlastsysoid,datfrozenxid,datacl,datfrozenxid64,datminmxid'
            )
        ]
    ),
    "pg_catalog.pg_foreign_server": Meta(
        Category.FDW,
        "存储外表服务器",
        True,
        [
            ContentRulesMeta(
                key='srvname',
                key_desc='外表服务器%s',
                filters=' oid < 10000 ',
                ignore_col='srvacl'
            ),
            ContentRulesMeta(
                complete_sql="select srvname, "
                             "       md5(fw.fdwname || fs.srvtype::text || fs.srvversion::text || fs.srvoptions::text) "
                             "from pg_foreign_server fs left join pg_foreign_data_wrapper fw on fs.srvfdw = fw.oid "
                             "where  9999 < fs.oid and fs.oid < 16384 ;",
                key_desc='外表服务器%s',
                complete_sql_desc='校验系统表pg_foreign_server的内容'
            )
        ]
    ),
    "pg_catalog.pg_user_mapping": Meta(
        Category.FDW,
        "存储外表用户映射关系",
        True,
        [
            ContentRulesMeta(
                filters=' umuser < 16384 and umserver < 16384 '
            )
        ]
    ),
    "pg_catalog.pg_foreign_data_wrapper": Meta(
        Category.FDW,
        "存外部数据包装器",
        True,
        [
            ContentRulesMeta(
                key='fdwname',
                key_desc='外部数据包装器%s',
                ignore_col='fdwacl',
                filters=' oid < 10000 '
            ),
            ContentRulesMeta(
                complete_sql="select fdw.fdwname, format('hander(%s),validator(%s)', p1.proname, p2.proname) "
                             "from pg_foreign_data_wrapper fdw left join pg_proc p1 on fdwhandler = p1.oid "
                             "                                 left join pg_proc p2 on fdwvalidator=p2.oid "
                             "where 9999 < fdw.oid and fdw.oid < 16384 ",
                key_desc='外部数据包装器%s',
                complete_sql_desc='校验表pg_foreign_data_wrapper的内容'
            )
        ]
    ),
    "pg_catalog.pg_shdescription": Meta(
        Category.DESCRIPTION,
        "存储共享数据库对象的注释",
        True,
        [
            ContentRulesMeta(
                filters=' objoid < 16384 and classoid < 16384 ',
                oid_col='objoid,classoid',
                accuracy=Accuracy.ALLOW_MORE
            )
        ]
    ),
    "pg_catalog.pg_aggregate": Meta(
        Category.FUNCTION,
        "存储聚集函数",
        True,
        [
            ContentRulesMeta(
                key='aggfnoid::oid',
                key_desc='oid为%s的聚集函数',
                filters=' aggfnoid < 10000 '
            ),
            ContentRulesMeta(
                key="format('%s %s %s %s', aggfnoid, aggtransfn, aggcollectfn, aggfinalfn)",
                key_desc='函数名、三阶段为%s的聚集函数',
                filters=' 9999 < aggfnoid and aggfnoid < 16384 '
                # aggfnoid是regproc类型，自动会按照字符串打印，无需做oid特殊处理
            )
        ]
    ),
    "pg_catalog.pg_am": Meta(
        Category.AM,
        "存储数据库索引相关相关的访问方法",
        True,
        [
            ContentRulesMeta(
                key='amname',
                key_desc='访问方法%s',
                filters=' oid < 10000 '
            ),
            ContentRulesMeta(
                key="amname",
                key_desc='访问方法%s',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid',
                oid_col='amkeytype'
            )
        ]
    ),
    "pg_catalog.pg_amop": Meta(
        Category.AM,
        "存储有关和访问方法操作符族关联的信息",
        True,
        [
            ContentRulesMeta(
                key="format('%s-%s-%s-%s', amopfamily, amoplefttype, amoprighttype, amopstrategy)",
                key_desc='family-ltype-rtype-stg为%s的操作符访问族',
                filters=' oid < 10000 '
            ),
            ContentRulesMeta(
                key="format('%s-%s-%s-%s', amopfamily, amoplefttype, amoprighttype, amopstrategy)",
                key_desc='family-ltype-rtype-stg为%s的操作符访问族',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid',
                oid_col='amopfamily,amoplefttype,amoprighttype,amopopr,amopmethod,amopsortfamily'
            )
        ]
    ),
    "pg_catalog.pg_amproc": Meta(
        Category.AM,
        "存储有关与访问方法操作符族相关联的支持过程的信息",
        True,
        [
            ContentRulesMeta(
                key="format('%s-%s-%s-%s', amprocfamily, amproclefttype, amprocrighttype, amprocnum)",
                key_desc='family-ltype-rtype-prn为%s的函数访问族',
                filters=' oid < 10000 '
            ),
            ContentRulesMeta(
                key="format('%s-%s-%s-%s', amprocfamily, amproclefttype, amprocrighttype, amprocnum)",
                key_desc='family-ltype-rtype-prn为%s的函数访问族',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid',
                oid_col='amprocfamily,amproclefttype,amprocrighttype'
            )
        ]
    ),
    "pg_catalog.pg_attrdef": Meta(
        Category.TABLE,
        "存储列的默认值",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid编号为%s的列默认值',
                filters=' oid < 10000 ',
                ignore_col='adbin_on_update,adbin'
            ),
            ContentRulesMeta(
                key="format('%s-%s', (select relname from pg_class c where c.oid=adrelid), adnum)",
                key_desc='表名-列号为%s的列默认值',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid,adbin_on_update,adbin',
                oid_col='adrelid'
            )
        ]
    ),
    "pg_catalog.pg_cast": Meta(
        Category.TYPE,
        "存储数据类型转换方式",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid编号为%s的数据类型转换方式',
                filters=' oid < 10000 '
            ),
            ContentRulesMeta(
                key="format('%s-%s', (select typname from pg_type t where t.oid=castsource), "
                    "(select typname from pg_type t where t.oid=casttarget))",
                key_desc='左右类型为%s的转换方法',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid',
                oid_col='castsource,casttarget,castfunc,castowner',
                accuracy=Accuracy.ALLOW_MORE
            )
        ]
    ),
    "pg_catalog.pg_constraint": Meta(
        Category.CONSTRAINT,
        "存储表上的检查约束、主键和唯一约束",
        True,
        [
            ContentRulesMeta(
                key='oid',
                key_desc='oid编号为%s的约束',
                filters=' oid < 10000 ',
                ignore_col='conbin'
            ),
            ContentRulesMeta(
                key="conname",
                key_desc='约束%s',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid,conpfeqop,conppeqop,conffeqop,conexclop,conbin',
                oid_col='connamespace,conrelid,contypid,conindid,confrelid'
            ),
            ContentRulesMeta(
                complete_sql="select format('def:%s', conname), md5(pg_get_constraintdef(oid)) "
                             "from pg_constraint "
                             "where oid < 16384 ",
                key_desc='约束%s的定义',
                complete_sql_desc='通过pg_get_constraintdef()函数检查oid < 16384的约束的定义'
            )
        ]
    ),
    "pg_catalog.pg_conversion": Meta(
        Category.LOCALE,
        "存储编码转换信息",
        True,
        [
            ContentRulesMeta(
                key='oid',
                key_desc='oid为%s的编码转换方式',
                filters=' oid < 10000 '
            ),
            ContentRulesMeta(
                key="format('%s.%s', (select nspname from pg_namespace n where n.oid=connamespace), conname)",
                key_desc='编码转换方式%s',
                filters=' 9999 < oid and oid < 16384 ',
                oid_col='oid,connamespace,conowner,conforencoding,contoencoding,conproc'
            )
        ]
    ),
    "pg_catalog.pg_depend": Meta(
        Category.DEPEND,
        "记录数据库非共享对象之间的依赖性关系",
        True
        # pg_depend的内容太多且场景太复杂，暂时无法总结规律并写出SQL。
        # 在直接安装时，很多内置对象直接写入系统表，进而未配置依赖关系，例如一些函数等，但通过升级脚本创建的则可以。
        # 同时夹杂着太多的1W~16384的内容
        # 考虑此系统表的含义，仅是一个依赖的属性，对应的实体对象会在其他系统表内校验，因此暂时不进行此系统表的校验
    ),
    "pg_catalog.pg_description": Meta(
        Category.DESCRIPTION,
        "存储数据库对象的描述",
        True,
        [
            ContentRulesMeta(
                key="format('%s-%s-%s', objoid, classoid, objsubid)",
                key_desc='obj-class-subid为%s的描述',
                filters=' objoid < 10000 and classoid < 10000 and objsubid < 10000 ',
                oid_col='objoid,classoid'
            ),
            # 1W+比较难写，仅测试数量，问题不大。
            ContentRulesMeta(
                complete_sql = "select format('%s-%s-%s', "
                               "              (case when objoid < 9999 then objoid else 0 end), "
                               "              (case when classoid < 9999 then classoid else 0 end), "
                               "              (case when objsubid < 9999 then objsubid else 0 end) "
                               "       ) as key,"
                               "       count(*) as val "
                               "from pg_description "
                               "where (9999 < objoid and objoid < 16384) or "
                               "      (9999 < classoid and classoid < 16384) or "
                               "      (9999 < objsubid and objsubid < 16384) "
                               "group by key;",
                key_desc = '(9999,16384)的范围内的键值为%s(1W+显示0)的注释数量',
                complete_sql_desc = '统计(9999,16384)的范围内的(oid在1W+时显示0)的注释数量'
            )
        ]
    ),
    "pg_catalog.pg_index": Meta(
        Category.INDEX,
        "存储索引的信息",
        True,
        [
            ContentRulesMeta(
                key='indexrelid',
                key_desc='indexrelid为%s的索引',
                filters=' indexrelid < 10000 ',
                ignore_col='indpred,indexprs'
            ),
            ContentRulesMeta(
                key="format('%s-%s',"
                    " (select relname from pg_class c where c.oid=indrelid),"
                    " (select relname from pg_class c where c.oid=indexrelid)"
                    ")",
                key_desc='表名-索引名为%s的索引',
                filters=" 9999 < indexrelid and  indexrelid < 16384 and "
                        "(select relkind from pg_class c where c.oid=indrelid) != 't'",
                ignore_col='indcollation,indclass',
                oid_col='indexrelid,indrelid'
            ),
            ContentRulesMeta(
                complete_sql="select format('def:%s(%s)', ct.relname, ci.relname), "
                             "       md5(pg_get_indexdef(indexrelid)) "
                             "from pg_index i left join pg_class ct on i.indrelid = ct.oid "
                             "                left join pg_class ci on i.indexrelid = ci.oid "
                             "where indexrelid < 16384 and ct.relnamespace not in (99, 4989)",
                key_desc='索引定义%s',
                complete_sql_desc='通过函数pg_get_indexdef()校验索引的定义（排除pg_toast、snapshot的索引，因为有会变OID名字等原因）'
            )
        ]
    ),
    "pg_catalog.pg_inherits": Meta(
        Category.TABLE,
        "记录关于表继承层次的信息",
        True,
        [
            ContentRulesMeta(
                key="format('%s-%s', (case when inhrelid < 10000 then inhrelid else 0 end), inhseqno)",
                key_desc='表-继承号为%s的继承关系',
                oid_col='inhrelid,inhparent',
                accuracy=Accuracy.ALLOW_MORE
            )
        ]
    ),
    "pg_catalog.pg_language": Meta(
        Category.LANGUAGE,
        "存储编程语言，用户可以用这些语言或接口写函数或者存储过程",
        True,
        [
            ContentRulesMeta(
                key='lanname',
                key_desc='oid为%s的语言',
                filters=' oid < 10000 ',
                ignore_col='lanacl'
            ),
            ContentRulesMeta(
                key='lanname',
                key_desc='名称为%s的语言',
                filters=' 9999 < oid and oid < 10000 ',
                ignore_col='lanacl',
                oid_col='oid,lanplcallfoid,laninline,lanvalidator'
            )
        ]
    ),
    "pg_catalog.pg_largeobject": Meta(
        Category.LOB,
        "保存那些标记着'大对象'的数据",
        True,
        [
            ContentRulesMeta(
                key="format('%s %s', loid, pageno)",
                key_desc='loid-pageno为%s的大对象',
                accuracy=Accuracy.ALLOW_MORE
            )
        ]
    ),
    "pg_catalog.pg_namespace": Meta(
        Category.SCHEMA,
        "存储名称空间，即schema相关的信息",
        True,
        [
            ContentRulesMeta(
                key='nspname',
                key_desc='名称为%s的schema',
                filters=' oid < 10000 ',
                ignore_col='nsptimeline,nspacl,in_redistribution,nspblockchain,nspcollation'
            ),
            ContentRulesMeta(
                key='nspname',
                key_desc='名称为%s的schema',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='nsptimeline,nspacl,in_redistribution,nspblockchain,nspcollation',
                oid_col='oid,nspowner'
            )
        ]
    ),
    "pg_catalog.pg_opclass": Meta(
        Category.OPERATOR,
        "存储索引访问方法操作符类",
        True,
        [
            ContentRulesMeta(
                key='oid',
                key_desc='oid为%s的操作符类',
                filters=' oid < 10000 '
            ),
            ContentRulesMeta(
                key="format('%s.%s(of am %s)',"
                    " opcnamespace,"
                    " opcname,"
                    " (select amname from pg_am a where a.oid=opcmethod)"
                    ")",
                key_desc='操作符类%s',
                filters=' 9999 < oid and oid < 16384 ',
                oid_col='oid,opcmethod,opcnamespace,opcowner,opcfamily,opcintype,opckeytype'
            )
        ]
    ),
    "pg_catalog.pg_operator": Meta(
        Category.OPERATOR,
        "存储有关操作符的信息",
        True,
        [
            ContentRulesMeta(
                key='oid',
                key_desc='oid为%s的操作符',
                filters=' oid < 10000 ',
                ignore_col='oprnamespace,oprowner,oprleft,oprright,oprresult,oprcom,oprnegate'
            ),
            ContentRulesMeta(
                key="format('%s.(%s %s %s)',"
                    " (select nspname from pg_namespace where oid=oprnamespace), "
                    " (select typname from pg_type t where t.oid=oprleft), "
                    " oprname, "
                    " (select typname from pg_type t where t.oid=oprright) "
                    ")",
                key_desc='操作符 %s',
                filters=' 9999 < oid and oid < 16384 ',
                oid_col='oid,oprnamespace,oprowner,oprleft,oprright,oprresult,oprcom,oprnegate'
            )
        ]
    ),
    "pg_catalog.pg_rewrite": Meta(
        Category.RULE,
        "存储为表和视图定义的重写规则",
        True,
        [
            ContentRulesMeta(
                key='oid',
                key_desc='oid为%s的操作符',
                filters=' oid < 10000 ',
                ignore_col='ev_action,ev_qual'
            ),
            ContentRulesMeta(
                key="format('%s(on %s)', rulename, (select relname from pg_class c where c.oid=ev_class))",
                key_desc='重写规则%s',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='ev_qual,ev_action',
                oid_col='oid,ev_class'
            ),
            ContentRulesMeta(
                complete_sql="select format('def:%s.%s(%s)', n.nspname, c.relname, r.rulename), "
                             "       md5(pg_get_ruledef(r.oid)) "
                             "from pg_rewrite r left join pg_class c on r.ev_class = c.oid "
                             "                  left join pg_namespace n on c.relnamespace = n.oid "
                             "where r.oid < 16384 and "
                             "      n.nspname not in ('pg_toast', 'snapshot');",
                key_desc='规则定义%s',
                complete_sql_desc='使用函数pg_get_ruledef校验重写规则的定义'
            )
        ]
    ),
    "pg_catalog.pg_statistic": Meta(
        Category.OPTIMIZER,
        "存储用于优化器行数估算的统计信息",
        True
        # 不用校验内容
    ),
    "pg_catalog.pg_trigger": Meta(
        Category.TRIGGER,
        "存储触发器信息",
        True,
        [
            ContentRulesMeta(
                key='oid',
                key_desc='oid为%s的触发器',
                filters=' oid < 10000 ',
                ignore_col='tgtime,tgqual'
            ),
            ContentRulesMeta(
                key="format('%s(on %s)', tgname, (select relname from pg_class c where c.oid=tgrelid))",
                key_desc='触发器%s',
                filters=' 9999 < oid and oid < 16384 ',
                oid_col='oid,tgrelid',
                ignore_col='tgtime,tgqual'
            ),
            ContentRulesMeta(
                complete_sql="select format('def:%s(%s)', c.relname, t.tgname), "
                             "       md5(pg_get_triggerdef(t.oid)) "
                             "from pg_trigger t left join pg_class c on t.tgrelid=c.oid "
                             "where t.oid < 16384 ",
                key_desc='触发器定义%s',
                complete_sql_desc='通过函数pg_get_triggerdef()检查触发器的定义'
            )
        ]
    ),
    "pg_catalog.pg_opfamily": Meta(
        Category.OPERATOR,
        "存储操作符族",
        True,
        [
            ContentRulesMeta(
                key='oid',
                key_desc='oid为%s的触发器',
                filters=' oid < 10000 '
            ),
            ContentRulesMeta(
                key="format('%s.%s(for %s)', "
                    " (select nspname from pg_namespace n where n.oid=opfnamespace), "
                    " opfname, "
                    " (select amname from pg_am a where a.oid=opfmethod) "
                    ")",
                key_desc='操作符族%s',
                filters=' 9999 < oid and oid < 16384 ',
                oid_col='opfmethod,opfnamespace,opfowner'
            )
        ]
    ),
    "pg_catalog.pg_db_role_setting": Meta(
        Category.AUTHENTICATION,
        "存储数据库运行时每个角色与数据绑定的配置项的默认值",
        True,
        [
            ContentRulesMeta(
                key="format('%s(of db %s)', "
                    " setrole, "
                    " (select datname from pg_database d where d.oid=setdatabase) "
                    ")",
                key_desc='用户%s的配置默认值',
                filters=' setdatabase < 16384 and setrole < 16384 '
            )
        ]
    ),
    "pg_catalog.pg_largeobject_metadata": Meta(
        Category.LOB,
        "存储与大数据相关的元数据",
        True,
        [
            ContentRulesMeta(
                key="lomowner",
                key_desc='oid为%s的大对象元数据',
                filters=' oid < 16384 ',
                ignore_col='lomacl',
                accuracy=Accuracy.ALLOW_MORE
            )
        ]
    ),
    "pg_catalog.pg_extension": Meta(
        Category.EXTENSION,
        "存储关于所安装扩展的信息",
        True,
        [
            ContentRulesMeta(
                key="extname",
                key_desc='扩展%s',
                filters=' oid < 10000 ',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="extname",
                key_desc='扩展%s',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='extconfig',
                oid_col='oid,extowner,extnamespace',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_foreign_table": Meta(
        Category.TABLE,
        "存储外部表的辅助信息",
        True,
        [
            ContentRulesMeta(
                key="ftrelid",
                key_desc='oid为%s的外表',
                filters=' ftrelid < 10000 ',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="(select relname from pg_class c where c.oid=ftrelid)",
                key_desc='外表%s',
                filters=' 9999 < ftrelid and ftrelid < 10000 ',
                oid_col='ftrelid,ftserver',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_statistic_ext": Meta(
        Category.OPTIMIZER,
        "存储有关该数据库中表的扩展统计数据，包括多列统计数据和表达式统计数据",
        True
        # 无需校验内容
    ),
    "pg_catalog.pg_rlspolicy": Meta(
        Category.PRIVILEGE,
        "存储行级访问控制策略",
        True,
        [
            ContentRulesMeta(
                key='oid',
                key_desc='oid为%s的行级访问控制策略',
                filters=' oid < 10000 ',
                ignore_col='polqual',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="format('%s(on %s)', polname, (select relname from pg_class c where c.oid=polrelid))",
                key_desc='行级访问控制策略%s',
                filters=' 9999 < oid and oid < 10000 ',
                ignore_col='polqual',
                oid_col='oid,polrelid',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_resource_pool": Meta(
        Category.WLM,
        "提供了数据库资源池的信息",
        True,
        [
            ContentRulesMeta(
                key='oid',
                key_desc='oid为%s的资源池',
                filters=' oid < 10000 ',
                ignore_col='mem_percent,cpu_affinity,control_group,active_statements,max_dop,memory_limit,parentid,'
                           'io_limits,io_priority,nodegroup,is_foreign,max_worker',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="respool_name",
                key_desc='资源池respool_name',
                filters=' 9999 < oid and oid < 10000 ',
                ignore_col='mem_percent,cpu_affinity,control_group,active_statements,max_dop,memory_limit,parentid,'
                           'io_limits,io_priority,nodegroup,is_foreign,max_worker',
                oid_col='oid',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_workload_group": Meta(
        Category.WLM,
        "提供了数据库负载组的信息",
        True,
        [
            ContentRulesMeta(
                key='workload_gpname',
                key_desc='负载组%s',
                filters=' oid < 16384 ',
                ignore_col='act_statements',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_collation": Meta(
        Category.LOCALE,
        "存储了排序规则，本质上从一个SQL名称映射到操作系统本地类别",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的排序规则',
                filters=' oid < 10000 ',
                accuracy=Accuracy.STRICT
            )
            # initdb阶段的不需要校验，因为这部分的是gs_initdb读取了环境locale -a之后配置到pg_collation的，因此也算是纯用户数据。
        ]
    ),
    "pg_catalog.pg_auth_history": Meta(
        Category.AUTHENTICATION,
        "存储了角色的认证历史",
        True
        # 无需校验内容
    ),
    "pg_catalog.pg_user_status": Meta(
        Category.AUTHENTICATION,
        "存储了访问数据库用户的状态",
        True,
        # 无需校验内容
    ),
    "pg_catalog.pg_app_workloadgroup_mapping": Meta(
        Category.WLM,
        "存储了数据库负载映射组的信息",
        True,
        [
            ContentRulesMeta(
                key="appname",
                key_desc='负载映射组%s',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_event_trigger": Meta(
        Category.TRIGGER,
        "存储每个事件触发器的信息",
        True,
        [
            ContentRulesMeta(
                key="evtname",
                key_desc='事件触发器%s',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_enum": Meta(
        Category.TYPE,
        "存储枚举类型相关信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的枚举值',
                filters=' oid < 10000 ',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="format('%s(%s)',"
                    "       (select typname from pg_type t where t.oid=enumtypid),"
                    "       enumlabel"
                    ")",
                key_desc='枚举类型值%s',
                filters=' 9999 < oid and oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_set": Meta(
        Category.TYPE,
        "存储集合数据类型定义的元数据",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的集合值',
                filters=' oid < 10000 ',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="format('%s(%s)',"
                    "       (select typname from pg_type t where t.oid=settypid),"
                    "       setlabel"
                    ")",
                key_desc='集合类型值%s',
                filters=' 9999 < oid and oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_range": Meta(
        Category.TYPE,
        "存储关于范围类型的信息",
        True,
        [
            ContentRulesMeta(
                key="rngtypid",
                key_desc='rngtypid为%s的范围类型',
                filters=' rngtypid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_synonym": Meta(
        Category.SYNONYM,
        "存储同义词",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的同义词',
                filters=' oid < 10000 ',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="format('%s.%s', (select nspname from pg_namespace n where n.oid=synnamespace), synname)",
                key_desc='同义词%s',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid',
                oid_col='synnamespace,synowner',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_shseclabel": Meta(
        Category.SECURITY,
        "存储共享数据对象上的安全标签",
        True
        # 安全标签用户可以自行设置或取消，无需校验内容
    ),
    "pg_catalog.pg_seclabel": Meta(
        Category.SECURITY,
        "存储数据对象上的安全标签",
        True
        # 安全标签用户可以自行设置或取消，无需校验内容
    ),
    "pg_catalog.pg_ts_dict": Meta(
        Category.TS,
        "存储定义文本搜索字典的记录",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的文本搜索字典',
                filters=' oid < 10000 ',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="format('%s.%s', (select nspname from pg_namespace n where n.oid=dictnamespace), dictname)",
                key_desc='文本搜索字典%s',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid',
                oid_col='dictnamespace,dictowner,dicttemplate',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_ts_parser": Meta(
        Category.TS,
        "包含定义文本解析器的记录",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的文本解析器',
                filters=' oid < 10000 ',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="format('%s.%s', (select nspname from pg_namespace n where n.oid=prsnamespace), prsname)",
                key_desc='文本解析器%s',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid',
                oid_col='prsnamespace',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_ts_config": Meta(
        Category.TS,
        "包含表示文本搜索配置的记录",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的文本搜索配置',
                filters=' oid < 10000 ',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="format('%s.%s', (select nspname from pg_namespace n where n.oid=cfgnamespace), cfgname)",
                key_desc='文本搜索配置%s',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid',
                oid_col='cfgnamespace,cfgowner,cfgparser',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_ts_config_map": Meta(
        Category.TS,
        "包含为每个文本搜索配置的解析器的每个输出符号类型，显示哪个文本搜索字典应该被咨询、以什么顺序搜索的记录",
        True,
        [
            ContentRulesMeta(
                key="format('%s %s %s', mapcfg, maptokentype, mapseqno)",
                key_desc='键值为%s的行',
                filters=' mapcfg < 10000 ',
                accuracy=Accuracy.STRICT
            ),
            # 1W+的在common rule内
            ContentRulesMeta(
                complete_sql="select format('%s %s %s', c.cfgname, cm.maptokentype, mapseqno),"
                             "       md5(d.dictname)"
                             "from pg_ts_config_map cm left join pg_ts_config c on cm.mapcfg = c.oid "
                             "                         left join pg_ts_dict d on cm.mapdict = d.oid "
                             "where 9999 < cm.mapcfg and cm.mapcfg < 16384;",
                key_desc='(9999,16384)的mapcfg范围内的键值为%s的文本搜索配置',
                complete_sql_desc='(9999,16384)的mapcfg范围内的所有文本搜索配置项目',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_ts_template": Meta(
        Category.TS,
        "存储文本搜索模板",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的文本搜索模板',
                filters=' oid < 10000 ',
                accuracy=Accuracy.STRICT
            ),
            ContentRulesMeta(
                key="format('%s.%s', (select nspname from pg_namespace n where n.oid=tmplnamespace), tmplname)",
                key_desc='文本搜索模板%s',
                filters=' 9999 < oid and oid < 16384 ',
                ignore_col='oid',
                oid_col='tmplnamespace',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_model_warehouse": Meta(
        Category.AI,
        "存储AI引擎训练模型，其中包含模型，训练过程的详细描述",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的训练模型',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_extension_data_source": Meta(
        Category.EXTENSION,
        "存储外部数据源对象的信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的外部数据源对象的信息',
                filters=' oid < 16384 ',
                ignore_col='srcacl',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_directory": Meta(
        Category.DIRECTORY,
        "保存用户添加的directory对象",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的文件夹',
                filters=' oid < 16384 ',
                ignore_col='srcacl',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_db_privilege": Meta(
        Category.PRIVILEGE,
        "记录ANY权限的授予情况，每条记录对应一条授权信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的授权记录',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_obsscaninfo": Meta(
        Category.OBS,
        "OBS扫描信息",
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_obsscaninfo": Meta(
        Category.OBS,
        "OBS扫描信息",
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_global_chain": Meta(
        Category.SECURITY,
        "记录用户对防篡改用户表的修改操作信息，每条记录对应一次表级修改操作",
        True
        # 无需校验内容
    ),
    "pg_catalog.pg_subscription": Meta(
        Category.PUB_SUB,
        "存储所有现有的逻辑复制订阅",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的复制订阅',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_publication": Meta(
        Category.PUB_SUB,
        "存储所有现有的逻辑复制发布",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的复制发布',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_publication_rel": Meta(
        Category.PUB_SUB,
        "存储当前数据库中的表和publication之间的映射，这是一种多对多映射",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的发布表映射',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_replication_origin": Meta(
        Category.REPLICATION,
        "包含所有已创建的复制源，该表为全局共享表，即在每个节点上只有一份pg_replication_origin，而不是每个数据库一份",
        True,
        [
            ContentRulesMeta(
                key="roident",
                key_desc='roident为%s的复制源',
                filters=' roident < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_subscription_rel": Meta(
        Category.PUB_SUB,
        "包含每个订阅中每个被复制表的状态，是多对多的映射关系",
        True,
        [
            ContentRulesMeta(
                key="format('%s->%s', srsubid, srrelid)",
                key_desc='从复制源%s表的赋值关系',
                filters=' srsubid < 16384 or srrelid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_package": Meta(
        Category.PACKAGE,
        '存储PACKAGE内的信息',
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的package',
                filters=' oid < 16384 ',
                ignore_col='pkgacl',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_recyclebin": Meta(
        Category.RECYCLE_BIN,
        '描述了回收站对象的详细信息',
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的垃圾桶',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_txn_snapshot": Meta(
        Category.TRANSACTION,
        '"时间戳-CSN"映射表，周期性采样，并维护适当的时间范围，用于估算范围内的时间戳对应的CSN值',
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_uid": Meta(
        Category.TABLE,
        '存储了数据库中使用hasuids属性表的唯一标识元信息',
        True,
        [
            ContentRulesMeta(
                key="relid",
                key_desc='relid为%s的uid',
                filters=' relid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pgxc_class": Meta(
        Category.DISTRIBUTE,
        '存储每张表的复制或分布信息(openGauss此表无意义)',
        True,
        [
            ContentRulesMeta(
                key="pcrelid",
                key_desc='pcrelid为%s的表',
                filters=' pcrelid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pgxc_group": Meta(
        Category.DISTRIBUTE,
        '存储集群节点组信息',
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的节点组',
                filters=' oid < 16384 ',
                ignore_col='group_acl',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pgxc_node": Meta(
        Category.DISTRIBUTE,
        "存储集群节点信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的节点',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_partition": Meta(
        Category.TABLE,
        "存储数据库内所有分区表（partitioned table）、分区（table partition）、分区上toast表和分区索引（index partition）四类对象的信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的分区或分区索引',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_job": Meta(
        Category.JOB,
        "存储用户创建的定时任务的任务详细信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的定时任务',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_job_proc": Meta(
        Category.JOB,
        "对应PG_JOB表中每个任务的作业内容（包括：PL/SQL代码块、匿名块）",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的定时任务作业内容',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pg_object": Meta(
        Category.OBJECT,
        "存储限定类型对象（普通表、索引、序列、视图、存储过程和函数）的创建用户、创建时间和最后修改时间",
        True
        # 此表无法记录builtin与initdb阶段的对象，因此无需校验内容。
    ),
    "pg_catalog.pg_hashbucket": Meta(
        Category.TABLE,
        "存储hash bucket表的信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的bucket',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.streaming_stream": Meta(
        Category.DISTRIBUTE,
        "存储流相关的信息(openGauss内此表无意义)",
        True
        # 无需校验内容
    ),
    "pg_catalog.streaming_cont_query": Meta(
        Category.DISTRIBUTE,
        "存储流相关的信息(openGauss内此表无意义)",
        True
        # 无需校验内容
    ),
    "pg_catalog.streaming_reaper_status": Meta(
        Category.DISTRIBUTE,
        "存储流相关的信息(openGauss内此表无意义)",
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_job_attribute": Meta(
        Category.JOB,
        "存储定时任务的相关属性",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的定时任务属性',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.pgxc_slice": Meta(
        Category.DISTRIBUTE,
        "针对range范围分布和list分布创建的系统表，用来记录分布具体信息(openGauss内此表无意义)",
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_job_argument": Meta(
        Category.JOB,
        "存储定时任务的相关内容",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的定时任务内容',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_sql_patch": Meta(
        Category.OPTIMIZER,
        "存储所有SQL_PATCH的状态信息",
        True
        # 纯用户行为数据，无需校验内容。
    ),
    "pg_catalog.gs_global_config": Meta(
        Category.GUC,
        "记录了数据库实例初始化时，用户指定的参数值",
        True
        # 纯用户行为数据，无需校验内容。
    ),
    "pg_catalog.gs_policy_label": Meta(
        Category.WLM,
        "记录资源标签配置信息，一个资源标签对应着一条或多条记录，每条记录标记了数据库资源所属的资源标签",
        True
        # 纯用户行为数据，无需校验内容。
    ),
    "pg_catalog.gs_auditing_policy": Meta(
        Category.AUTHENTICATION,
        "记录统一审计的主体信息，每条记录对应一个设计策略",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的审计策略',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_auditing_policy_access": Meta(
        Category.AUTHENTICATION,
        "记录与DML数据库相关操作的统一审计信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的信息',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_auditing_policy_privileges": Meta(
        Category.AUTHENTICATION,
        "记录统一审计DDL数据库相关操作信息，每条记录对应一个设计策略",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的设计策略',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_asp": Meta(
        Category.DFX,
        "存储被持久化的ACTIVE SESSION PROFILE样本",
        True
        # 不需要校验内容
    ),
    "pg_catalog.gs_auditing_policy_filters": Meta(
        Category.AUTHENTICATION,
        "记录统一审计相关的过滤策略相关信息，每条记录对应一个设计策略",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的过滤策略',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_masking_policy": Meta(
        Category.SECURITY,
        "记录动态数据脱敏策略的主体信息，每条记录对应一个脱敏策略",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的动态数据脱敏策略',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_masking_policy_filters": Meta(
        Category.SECURITY,
        "记录动态数据脱敏策略对应的用户过滤条件，当用户条件满足FILTER条件时，对应的脱敏策略才会生效",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的用户过滤条件',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_masking_policy_actions": Meta(
        Category.SECURITY,
        "记录动态数据脱敏策略中相应的脱敏策略包含的脱敏行为，一个脱敏策略对应着该表的一行或多行记录",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的脱敏行为',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_encrypted_columns": Meta(
        Category.SECURITY,
        "记录密态等值特性中表的加密列相关信息，每条记录对应一条加密列信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的加密列',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_client_global_keys": Meta(
        Category.SECURITY,
        "记录密态等值特性中客户端加密主密钥相关信息，每条记录对应一个客户端加密主密钥",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的加密主密钥',
                filters=' oid < 16384 ',
                ignore_col='key_acl',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_column_keys": Meta(
        Category.SECURITY,
        "记录密态等值特性中列加密密钥相关信息，每条记录对应一个列加密密钥",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的列加密密钥',
                filters=' oid < 16384 ',
                ignore_col='key_acl',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_client_global_keys_args": Meta(
        Category.SECURITY,
        "记录密态等值特性中客户端加密主密钥相关元数据信息，每条记录对应客户端加密主密钥的一个键值对信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的加密主密钥键值对信息',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_column_keys_args": Meta(
        Category.SECURITY,
        "记录密态等值特性中客户端加密主密钥相关元数据信息，每条记录对应客户端加密主密钥的一个键值对信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的键值对信息',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_encrypted_proc": Meta(
        Category.SECURITY,
        "提供了密态函数/存储过程函数参数、返回值的原始数据类型，加密列等信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的加密信息',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_matview": Meta(
        Category.VIEW,
        "提供了关于数据库中每一个物化视图的信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的物化视图条目',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_matview_dependency": Meta(
        Category.VIEW,
        "提供了关于数据库中每一个增量物化视图、基表和mlog表的关联信息",
        True,
        [
            ContentRulesMeta(
                key="oid",
                key_desc='oid为%s的增量物化视图信息',
                filters=' oid < 16384 ',
                accuracy=Accuracy.STRICT
            )
        ]
    ),
    "pg_catalog.gs_opt_model": Meta(
        Category.AI,
        "是启用AiEngine执行计划时间预测功能时的数据表，记录机器学习模型的配置、训练结果、功能、对应系统函数、训练历史等相关信息",
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_wlm_user_resource_history": Meta(
        Category.WLM,
        "存储与用户使用资源相关的信息",
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_wlm_instance_history": Meta(
        Category.WLM,
        "存储与实例（数据库主节点或数据库节点）相关的资源使用相关信息",
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_wlm_session_query_info_all": Meta(
        Category.WLM,
        "显示当前数据库实例执行作业结束后的负载管理记录",
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_wlm_operator_info": Meta(
        Category.WLM,
        "显示执行作业结束后的算子相关的记录",
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_wlm_plan_operator_info": Meta(
        Category.WLM,
        "显示执行作业结束后计划算子级的相关的记录",
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_wlm_plan_encoding_table": Meta(
        Category.WLM,
        "显示计划算子级的编码信息",
        True
        # 无需校验内容
    ),
    "pg_catalog.gs_wlm_ec_operator_info": Meta(
        Category.WLM,
        "存储执行EC（Extension Connector）作业结束后的算子相关的记录",
        True
        # 无需校验内容
    ),
    "pg_catalog.plan_table_data": Meta(
        Category.OPTIMIZER,
        "存储了用户通过执行EXPLAIN PLAN收集到的计划信息",
        True
        # 无需校验内容
    ),
    "pg_catalog.statement_history": Meta(
        Category.DFX,
        "存储SQL语句的性能诊断信息",
        True
        # 不需要校验内容
    ),
    "dbe_pldeveloper.gs_source": Meta(
        Category.FUNCTION,
        "记录PLPGSQL对象（存储过程、函数、包、包体）编译相关信息",
        True
        # 此表文档注明了只记录用户自定义数据，因此不需要校验内容

    ),
    "dbe_pldeveloper.gs_errors": Meta(
        Category.FUNCTION,
        "用于记录PLPGSQL对象（存储过程、函数、包、包体）编译过程中遇到的报错信息",
        True
        # 此表与gs_source一类，因此不需要校验内容
    ),
    "information_schema.sql_features": Meta(
        Category.INFO_SCHEMA,
        "用于记录一些sql特性相关信息",
        True,
    ),
    "information_schema.sql_implementation_info": Meta(
        Category.INFO_SCHEMA,
        "用于记录一些sql特性相关信息",
        True,
    ),
    "information_schema.sql_languages": Meta(
        Category.INFO_SCHEMA,
        "用于记录一些语言特性相关信息",
        True,
    ),
    "information_schema.sql_packages": Meta(
        Category.INFO_SCHEMA,
        "用于记录一些package特性相关信息",
        True,
    ),
    "information_schema.sql_parts": Meta(
        Category.INFO_SCHEMA,
        "用于记录一些sql parts特性相关信息",
        True,
    ),
    "information_schema.sql_sizing": Meta(
        Category.INFO_SCHEMA,
        "用于记录一些sql sizing特性相关信息",
        True,
    ),
    "information_schema.sql_sizing_profiles": Meta(
        Category.INFO_SCHEMA,
        "用于记录一些sql profiles特性相关信息",
        True,
    ),
    "db4ai.snapshot": Meta(
        Category.AI,
        "记录当前用户通过特性DB4AI.SNAPSHOT存储的快照",
        True
        # 无需校验内容
    ),
    "snapshot.tables_snap_timestamp": Meta(
        Category.WDR,
        "记录所有存储的WDR snapshot中数据库、表对象、以及数据采集的开始和结束时间",
        False
    ),
    "snapshot.snapshot": Meta(
        Category.WDR,
        "存储的WDR快照数据的索引信息、开始时间和结束时间",
        False
    ),
    "snapshot.snap_global_os_runtime": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_os_threads": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_instance_time": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_workload_sql_count": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_workload_sql_elapse_time": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_workload_transaction": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_workload_transaction": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_thread_wait_status": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_memory_node_detail": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False,
    ),
    "snapshot.snap_global_shared_memory_detail": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_stat_db_cu": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_stat_database": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_stat_database": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_stat_database_conflicts": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_stat_database_conflicts": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_stat_bad_block": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_stat_bad_block": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_file_redo_iostat": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_file_redo_iostat": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_rel_iostat": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_rel_iostat": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_file_iostat": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_file_iostat": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_replication_slots": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_bgwriter_stat": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_replication_stat": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_transactions_running_xacts": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_transactions_running_xacts": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_transactions_prepared_xacts": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_transactions_prepared_xacts": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_statement": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_statement_count": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_statement_count": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_config_settings": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_wait_events": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_user_login": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_ckpt_status": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_double_write_status": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_pagewriter_status": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_redo_status": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_rto_status": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_recovery_status": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_threadpool_status": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_statement_responsetime_percentile": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_statio_all_indexes": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_statio_all_indexes": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_statio_all_sequences": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_statio_all_sequences": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_statio_all_tables": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_statio_all_tables": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_stat_all_indexes": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_stat_all_indexes": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_stat_user_functions": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_stat_user_functions": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_stat_all_tables": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_summary_stat_all_tables": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_class_vital_info": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    ),
    "snapshot.snap_global_record_reset_time": Meta(
        Category.WDR,
        "存储用于生成WDR报告的相关数据",
        False
    )
}


def filter_uncertain_metas():
    uncertain_metas = []
    for key, meta in META.items():
        if not meta.certain:
            uncertain_metas.append(key)
    return uncertain_metas

