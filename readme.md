# KSubdomain: 极速无状态子域名爆破工具

V1.0
使用 crt.sh, rapiddns.io, hackertarget.com 网站做子域名收集

V1.0 修改版
添加 fofa.info 支持，需要在目录下添加config.json
内容为
{
  "fofa": {
    "enabled": true,
    "email": "XXX",
    "key": "XXX",
    "size": 10000
  }
}

## 📖 使用说明
# 使用免费数据源 + 内置字典
./ksubdomain enum -d example.com

# 多域名
./ksubdomain enum -d example.com -d test.com

# 从文件读取域名列表
./ksubdomain enum --domain-list domains.txt

# 仅使用在线源
./ksubdomain enum -d example.com --online-only

# 禁用在线源，仅字典爆破
./ksubdomain enum -d example.com --no-online

# 使用自定义字典
./ksubdomain enum -d example.com -f custom_dict.txt

# 启用NS记录查询
./ksubdomain enum -d example.com --ns

# 指定输出格式
./ksubdomain enum -d example.com -o results.json --output-type json

