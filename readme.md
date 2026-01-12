# KSubdomain: 极速无状态子域名爆破工具

添加crt等网站做子域名收集

## 📖 使用说明

```bash
KSubdomain - 极速无状态子域名爆破工具

用法:
  ksubdomain [全局选项] 命令 [命令选项] [参数...]

版本:
  查看版本信息: ksubdomain --version

命令:
  enum, e    枚举模式: 提供主域名进行爆破
  verify, v  验证模式: 提供域名列表进行验证
  test       测试本地网卡最大发包速度
  help, h    显示命令列表或某个命令的帮助

全局选项:
  --help, -h     显示帮助 (默认: false)
  --version, -v  打印版本信息 (默认: false)
```

### 验证模式 (Verify)

验证模式用于快速检查提供的域名列表的存活状态。

```bash
./ksubdomain verify -h # 查看验证模式帮助，可缩写 ksubdomain v

USAGE:
   ksubdomain verify [command options] [arguments...]

OPTIONS:
   --filename value, -f value       验证域名的文件路径
   --domain value, -d value         域名
   --band value, -b value           宽带的下行速度，可以5M,5K,5G (default: "3m")
   --resolvers value, -r value      dns服务器，默认会使用内置dns
   --output value, -o value         输出文件名
   --output-type value, --oy value  输出文件类型: json, txt, csv (default: "txt")
   --silent                         使用后屏幕将仅输出域名 (default: false)
   --retry value                    重试次数,当为-1时将一直重试 (default: 3)
   --timeout value                  超时时间 (default: 6)
   --stdin                          接受stdin输入 (default: false)
   --not-print, --np                不打印域名结果 (default: false)
   --eth value, -e value            指定网卡名称
   --wild-filter-mode value         泛解析过滤模式[从最终结果过滤泛解析域名]: basic(基础), advanced(高级), none(不过滤ne")
   --predict                        启用预测域名模式 (default: false)
   --help, -h                       show help (default: false)

# 示例:
# 验证多个域名解析
./ksubdomain v -d xx1.example.com -d xx2example.com

# 从文件读取域名进行验证，保存为 output.txt
./ksubdomain v -f domains.txt -o output.txt

# 从标准输入读取域名，带宽限制为 10M
cat domains.txt | ./ksubdomain v --stdin -b 10M

# 启用预测模式，泛解析过滤，保存为csv
./ksubdomain v -f domains.txt --predict --wild-filter-mode advanced --oy csv -o output.csv

# 默认：在线源 + 字典爆破
./ksubdomain enum -d example.com

# 仅使用在线源
./ksubdomain enum -d example.com --online-only

# 仅使用字典（禁用在线源）
./ksubdomain enum -d example.com --no-online

# 使用自定义字典
./ksubdomain enum -d example.com -f subdomains.txt --online-only

# 多域名
./ksubdomain enum -d example.com -d test.com

```

### 枚举模式 (Enum)

枚举模式基于字典和预测算法爆破指定域名下的子域名。

```bash
./ksubdomain enum -h # 查看枚举模式帮助,可简写 ksubdomain e

USAGE:
   ksubdomain enum [command options] [arguments...]

OPTIONS:
   --domain value, -d value         域名
   --band value, -b value           宽带的下行速度，可以5M,5K,5G (default: "3m")
   --resolvers value, -r value      dns服务器，默认会使用内置dns
   --output value, -o value         输出文件名
   --output-type value, --oy value  输出文件类型: json, txt, csv (default: "txt")
   --silent                         使用后屏幕将仅输出域名 (default: false)
   --retry value                    重试次数,当为-1时将一直重试 (default: 3)
   --timeout value                  超时时间 (default: 6)
   --stdin                          接受stdin输入 (default: false)
   --not-print, --np                不打印域名结果 (default: false)
   --eth value, -e value            指定网卡名称
   --wild-filter-mode value         泛解析过滤模式[从最终结果过滤泛解析域名]: basic(基础), advanced(高级), none(不过滤) (default: "none")
   --predict                        启用预测域名模式 (default: false)
   --filename value, -f value       字典路径
   --ns                             读取域名ns记录并加入到ns解析器中 (default: false)
   --help, -h                       show help (default: false)

# 示例:
# 枚举多个域名
./ksubdomain e -d example.com -d hacker.com

# 从文件读取字典枚举，保存为 output.txt
./ksubdomain e -f sub.dict -o output.txt

# 从标准输入读取域名，带宽限制为 10M
cat domains.txt | ./ksubdomain e --stdin -b 10M

# 启用预测模式枚举域名，泛解析过滤，保存为csv
./ksubdomain e -d example.com --predict --wild-filter-mode advanced --oy csv -o output.csv

# 默认：在线源 + 字典爆破
./ksubdomain enum -d example.com

# 仅使用在线源
./ksubdomain enum -d example.com --online-only

# 仅使用字典（禁用在线源）
./ksubdomain enum -d example.com --no-online

# 使用自定义字典
./ksubdomain enum -d example.com -f subdomains.txt --online-only

# 多域名
./ksubdomain enum -d example.com -d test.com

```
