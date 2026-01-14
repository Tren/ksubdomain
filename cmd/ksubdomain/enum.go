// cmd/ksubdomain/enum.go
package main

import (
    "bufio"
    "context"
    "math/rand"  // 保留 math/rand，因为使用了 rand.Intn
    "os"
    "strings"    // 保留 strings，因为使用了 strings.Join 等函数

    // 删除 fmt 导入
    core2 "github.com/boy-hack/ksubdomain/v2/pkg/core"
    "github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
    "github.com/boy-hack/ksubdomain/v2/pkg/core/ns"
    "github.com/boy-hack/ksubdomain/v2/pkg/core/options"
    "github.com/boy-hack/ksubdomain/v2/pkg/runner"
    "github.com/boy-hack/ksubdomain/v2/pkg/runner/outputter"
    output2 "github.com/boy-hack/ksubdomain/v2/pkg/runner/outputter/output"
    processbar2 "github.com/boy-hack/ksubdomain/v2/pkg/runner/processbar"
    "github.com/urfave/cli/v2"
)


// 修改 enumCommand 的 Action 函数，以下是修改后的完整 Action 函数
var enumCommand = &cli.Command{
    Name:    "enum",
    Aliases: []string{"e"},
    Usage:   "枚举域名 - 自动从在线源收集子域名后进行爆破",
    Flags: append(CommonFlags, []cli.Flag{
        &cli.StringFlag{
            Name:     "filename",
            Aliases:  []string{"f"},
            Usage:    "字典文件路径，如未指定则使用内置字典",
            Required: false,
            Value:    "",
        },
        &cli.BoolFlag{
            Name:    "ns",
            Usage:   "读取域名的NS记录并添加到解析器中",
            Value:   false,
        },
        &cli.StringFlag{
            Name:    "domain-list",
            Aliases: []string{"ds"},
            Usage:   "从文件读取域名列表，每行一个",
            Value:   "",
        },
        &cli.BoolFlag{
            Name:    "online-only",
            Usage:   "仅使用在线源获取的子域名，不结合字典爆破",
            Value:   false,
        },
        &cli.BoolFlag{
            Name:    "no-online",
            Usage:   "禁用所有在线子域名查询，仅使用字典爆破",
            Value:   false,
        },
    }...),
    Action: func(c *cli.Context) error {
        gologger.Printf("\n")
        gologger.Infof("========== KSubdomain 子域名枚举工具 ==========\n")
        gologger.Infof("版本：2.0 (增强版，支持多在线数据源)\n")
        gologger.Infof("===============================================\n")

        if c.NumFlags() == 0 && c.NArg() == 0 {
            gologger.Errorf("错误：未提供任何参数\n")
            gologger.Printf("使用 --help 查看使用说明\n")
            return cli.Exit("", 1)
        }

        var domains []string
        processBar := &processbar2.ScreenProcess{Silent: c.Bool("silent")}

        // ==================== 收集域名 ====================
        gologger.Infof("[1/5] 正在收集目标域名...\n")
        
        if c.StringSlice("domain") != nil {
            for _, d := range c.StringSlice("domain") {
                d = strings.TrimSpace(d)
                if d != "" && !contains(domains, d) {
                    domains = append(domains, d)
                }
            }
        }
        
        if c.Bool("stdin") {
            scanner := bufio.NewScanner(os.Stdin)
            scanner.Split(bufio.ScanLines)
            for scanner.Scan() {
                d := strings.TrimSpace(scanner.Text())
                if d != "" && !contains(domains, d) {
                    domains = append(domains, d)
                }
            }
        }
        
        if c.String("domain-list") != "" {
            filename := c.String("domain-list")
            f, err := os.Open(filename)
            if err != nil {
                gologger.Fatalf("打开文件 %s 失败：%s\n", filename, err.Error())
            }
            defer f.Close()
            
            scanner := bufio.NewScanner(f)
            scanner.Split(bufio.ScanLines)
            for scanner.Scan() {
                d := strings.TrimSpace(scanner.Text())
                if d != "" && !strings.HasPrefix(d, "#") && !contains(domains, d) {
                    domains = append(domains, d)
                }
            }
        }

        if len(domains) == 0 {
            gologger.Fatalf("错误：未指定要枚举的域名\n")
        }

        gologger.Infof("收集到 %d 个目标域名：\n", len(domains))
        for i, domain := range domains {
            gologger.Printf("  [%d] %s\n", i+1, domain)
        }
        gologger.Printf("\n")

        // ==================== 泛解析检测 ====================
        gologger.Infof("[2/5] 正在检测泛解析...\n")
        wildIPS := make([]string, 0)
        if c.String("wild-filter-mode") != "none" {
            for _, domain := range domains {
                ok, ips := runner.IsWildCard(domain)
                if ok {
                    wildIPS = append(wildIPS, ips...)
                    gologger.Warningf("检测到泛解析域名：%s (IP: %v)\n", domain, ips)
                }
            }
            gologger.Infof("泛解析检测完成\n")
        }
        gologger.Printf("\n")

        // ==================== 在线子域名收集 ====================
        var onlineSubdomains map[string][]string
        
        if !c.Bool("no-online") {
            gologger.Infof("[3/5] 开始从在线数据源收集子域名...\n")
            
            // 显示正在加载的配置文件信息
            config, err := LoadGlobalConfig()
            if err == nil {
                enabledSources := []string{"crt.sh", "rapiddns.io", "hackertarget.com"}
                
                // 检查FOFA是否启用
                if config.Fofa != nil && config.Fofa.Enabled && config.Fofa.Email != "" && config.Fofa.Key != "" {
                    enabledSources = append(enabledSources, "fofa.info")
                    gologger.Infof("已启用 FOFA 数据源 (API用户: %s)\n", config.Fofa.Email)
		}

                
                // 检查其他付费源
                if config.VirusTotal != nil && config.VirusTotal.Enabled && config.VirusTotal.APIKey != "" {
                    enabledSources = append(enabledSources, "virustotal.com")
                    gologger.Infof("已启用 VirusTotal 数据源\n")
                }
                
                if config.BinaryEdge != nil && config.BinaryEdge.Enabled && config.BinaryEdge.APIKey != "" {
                    enabledSources = append(enabledSources, "binaryedge.io")
                    gologger.Infof("已启用 BinaryEdge 数据源\n")
                }
                
                if config.CertSpotter != nil && config.CertSpotter.Enabled {
                    enabledSources = append(enabledSources, "certspotter.com")
                    gologger.Infof("已启用 CertSpotter 数据源\n")
                }
                
                gologger.Infof("本次查询将使用 %d 个数据源: %s\n", 
                    len(enabledSources), strings.Join(enabledSources, ", "))
            } else {
                gologger.Infof("使用免费数据源: crt.sh, rapiddns.io, hackertarget.com\n")
            }
            
            gologger.Infof("开始查询在线数据源...\n")
            finder := NewOnlineSubdomainFinder()
            onlineSubdomains = finder.FindSubdomains(domains)
            
            // ==================== 显示详细统计 ====================
            gologger.Infof("========== 在线收集结果统计 ==========\n")
            
            totalOnline := 0
            for domain, subs := range onlineSubdomains {
                domainTotal := len(subs)
                totalOnline += domainTotal
                
                if domainTotal > 0 {
                    gologger.Infof("✓ %s: %d 个子域名\n", domain, domainTotal)
                    
                    // 显示前5个子域名作为示例
                    showCount := 5
                    if domainTotal < showCount {
                        showCount = domainTotal
                    }
                    for i := 0; i < showCount; i++ {
                        gologger.Printf("    - %s\n", subs[i])
                    }
                    if domainTotal > showCount {
                        gologger.Printf("    ... 还有 %d 个子域名\n", domainTotal-showCount)
                    }
                } else {
                    gologger.Infof("✗ %s: 未发现子域名\n", domain)
                }
                gologger.Printf("\n")
            }
            
            // ==================== 显示数据源统计摘要 ====================
            if totalOnline > 0 {
                gologger.Infof("========== 统计摘要 ==========\n")
                gologger.Infof("在线收集完成，共发现 %d 个唯一的子域名\n", totalOnline)
                
                // 根据配置显示实际使用的数据源
                if config != nil {
                    sourcesUsed := []string{"crt.sh", "rapiddns.io", "hackertarget.com"}
                    if config.Fofa != nil && config.Fofa.Enabled && config.Fofa.Email != "" && config.Fofa.Key != "" {
                        sourcesUsed = append(sourcesUsed, "FOFA")
                    }
                    if config.VirusTotal != nil && config.VirusTotal.Enabled && config.VirusTotal.APIKey != "" {
                        sourcesUsed = append(sourcesUsed, "VirusTotal")
                    }
                    if config.BinaryEdge != nil && config.BinaryEdge.Enabled && config.BinaryEdge.APIKey != "" {
                        sourcesUsed = append(sourcesUsed, "BinaryEdge")
                    }
                    if config.CertSpotter != nil && config.CertSpotter.Enabled {
                        sourcesUsed = append(sourcesUsed, "CertSpotter")
                    }
                    
                    gologger.Infof("本次查询使用了 %d 个数据源\n", len(sourcesUsed))
                    gologger.Infof("数据源列表: %s\n", strings.Join(sourcesUsed, ", "))
                    
                    // 特别提示FOFA的贡献
                    if config.Fofa != nil && config.Fofa.Enabled && config.Fofa.Email != "" && config.Fofa.Key != "" {
                        gologger.Infof("其中 FOFA 数据源已启用 (查询账号: %s)\n", config.Fofa.Email)
                        gologger.Infof("如需调整 FOFA 查询参数，请编辑当前目录下的 config.json 文件\n")
                    }
                } else {
                    gologger.Infof("本次查询使用了 3 个免费数据源\n")
                    gologger.Infof("数据源列表: crt.sh, rapiddns.io, hackertarget.com\n")
                    gologger.Infof("如需使用 FOFA、VirusTotal 等付费数据源，请在当前目录创建 config.json 文件\n")
                }
            } else {
                gologger.Infof("在线收集未发现子域名\n")
            }
            gologger.Infof("====================================\n")
        } else {
            gologger.Infof("[3/5] 在线子域名收集已禁用\n")
            onlineSubdomains = make(map[string][]string)
        }
        gologger.Printf("\n")

        // ==================== 字典爆破准备 ====================
        if c.Bool("online-only") {
            gologger.Infof("[4/5] 字典爆破已跳过 (--online-only)\n")
            
            totalOnline := 0
            for _, subs := range onlineSubdomains {
                totalOnline += len(subs)
            }
            
            if totalOnline == 0 {
                gologger.Fatalf("错误：未收集到任何子域名\n")
            }
            
            gologger.Infof("将扫描 %d 个在线收集的子域名\n", totalOnline)
        } else {
            gologger.Infof("[4/5] 正在准备字典爆破...\n")
            
            // 如果在线收集有结果，显示提示
            totalOnline := 0
            for _, subs := range onlineSubdomains {
                totalOnline += len(subs)
            }
            
            if totalOnline > 0 {
                gologger.Infof("已有 %d 个在线收集的子域名加入扫描队列\n", totalOnline)
            }
        }
        gologger.Printf("\n")

        // ==================== 创建子域名生成通道 ====================
        render := make(chan string, 10000)
        totalToScan := 0
        
        // 启动goroutine生成子域名
        go func() {
            defer close(render)
            
            sentSubdomains := make(map[string]bool)
            onlineCount := 0
            dictCount := 0
            
            // 第一阶段：发送从在线源获取的子域名
            for _, subdomains := range onlineSubdomains {
                for _, subdomain := range subdomains {
                    if !sentSubdomains[subdomain] {
                        sentSubdomains[subdomain] = true
                        render <- subdomain
                        onlineCount++
                    }
                }
            }
            
            if c.Bool("online-only") {
                totalToScan = onlineCount
                gologger.Infof("仅使用在线源，跳过字典爆破\n")
                return
            }
            
            // 第二阶段：字典爆破
            filename := c.String("filename")
            
            if filename == "" {
                subdomainDict := core2.GetDefaultSubdomainData()
                gologger.Infof("使用内置字典 (%d 个子域名前缀)\n", len(subdomainDict))
                
                for _, domain := range domains {
                    for _, sub := range subdomainDict {
                        target := sub + "." + domain
                        if !sentSubdomains[target] {
                            sentSubdomains[target] = true
                            render <- target
                            dictCount++
                        }
                    }
                }
                gologger.Infof("从内置字典生成了 %d 个新目标\n", dictCount)
            } else {
                gologger.Infof("使用自定义字典文件：%s\n", filename)
                f, err := os.Open(filename)
                if err != nil {
                    gologger.Fatalf("打开字典文件失败：%s\n", err.Error())
                }
                defer f.Close()
                
                scanner := bufio.NewScanner(f)
                for scanner.Scan() {
                    sub := strings.TrimSpace(scanner.Text())
                    if sub == "" || strings.HasPrefix(sub, "#") {
                        continue
                    }
                    
                    for _, domain := range domains {
                        target := sub + "." + domain
                        if !sentSubdomains[target] {
                            sentSubdomains[target] = true
                            render <- target
                            dictCount++
                        }
                    }
                }
                gologger.Infof("从自定义字典生成了 %d 个新目标\n", dictCount)
            }
            
            totalToScan = onlineCount + dictCount
            gologger.Infof("========== 扫描队列统计 ==========\n")
            gologger.Infof("在线收集目标: %d 个\n", onlineCount)
            gologger.Infof("字典生成目标: %d 个\n", dictCount)
            gologger.Infof("目标总数 (已去重): %d 个\n", totalToScan)
            gologger.Infof("================================\n")
        }()
        
        // ==================== NS记录查询 ====================
        gologger.Infof("[5/5] 正在进行扫描前准备...\n")
        
        specialDns := make(map[string][]string)
        defaultResolver := options.GetResolvers(c.StringSlice("resolvers"))
        
        if c.Bool("ns") {
            gologger.Infof("正在查询域名NS记录...\n")
            for _, domain := range domains {
                // 使用下划线忽略 nsServers，只保留 ips
                _, ips, err := ns.LookupNS(domain, defaultResolver[rand.Intn(len(defaultResolver))])
                if err != nil {
                    gologger.Warningf("查询 %s 的NS记录失败：%v\n", domain, err)
                    continue
                }
                specialDns[domain] = ips
            }
            gologger.Infof("NS记录查询完成\n")
        }
        
        // ==================== 配置输出器 ====================
        gologger.Debugf("正在配置输出...\n")
        
        screenWriter, err := output2.NewScreenOutput(c.Bool("silent"))
        if err != nil {
            gologger.Fatalf("创建屏幕输出器失败：%s\n", err.Error())
        }
        
        var writers []outputter.Output
        if !c.Bool("not-print") {
            writers = append(writers, screenWriter)
        }
        
        if c.String("output") != "" {
            outputFile := c.String("output")
            outputType := c.String("output-type")
            wildFilterMode := c.String("wild-filter-mode")
            
            gologger.Infof("结果将输出到：%s (%s 格式)\n", outputFile, outputType)
            
            switch outputType {
            case "txt":
                p, err := output2.NewPlainOutput(outputFile, wildFilterMode)
                if err != nil {
                    gologger.Fatalf("创建文本输出器失败：%s\n", err.Error())
                }
                writers = append(writers, p)
            case "json":
                p := output2.NewJsonOutput(outputFile, wildFilterMode)
                writers = append(writers, p)
            case "csv":
                p := output2.NewCsvOutput(outputFile, wildFilterMode)
                writers = append(writers, p)
            default:
                gologger.Fatalf("不支持的输出类型：%s (支持：txt, json, csv)\n", outputType)
            }
        }
        
        // ==================== 配置扫描器 ====================
        gologger.Debugf("正在配置扫描器参数...\n")
        
        opt := &options.Options{
            Rate:               options.Band2Rate(c.String("band")),
            Domain:             render,
            Resolvers:          defaultResolver,
            Silent:             c.Bool("silent"),
            TimeOut:            c.Int("timeout"),
            Retry:              c.Int("retry"),
            Method:             options.VerifyType,
            Writer:             writers,
            ProcessBar:         processBar,
            SpecialResolvers:   specialDns,
            WildcardFilterMode: c.String("wild-filter-mode"),
            WildIps:            wildIPS,
            Predict:            c.Bool("predict"),
        }
        
        opt.Check()
        opt.EtherInfo = options.GetDeviceConfig(defaultResolver)
        
        // ==================== 开始扫描 ====================
        gologger.Printf("\n")
        gologger.Infof("========== 开始子域名扫描 ==========\n")
        gologger.Infof("目标总数：%d\n", totalToScan)
        gologger.Infof("DNS解析器：%d 个\n", len(defaultResolver))
        gologger.Infof("扫描速率：%s\n", c.String("band"))
        gologger.Infof("泛解析过滤：%s\n", c.String("wild-filter-mode"))
        gologger.Infof("=====================================\n")
        gologger.Printf("\n")
        
        ctx := context.Background()
        r, err := runner.New(opt)
        if err != nil {
            gologger.Fatalf("创建扫描器失败：%s\n", err.Error())
        }
        
        r.RunEnumeration(ctx)
        r.Close()
        
        // ==================== 扫描完成 ====================
        gologger.Printf("\n")
        gologger.Infof("========== 扫描完成 ==========\n")
        gologger.Infof("所有任务已处理完毕\n")
        
        if c.String("output") != "" {
            gologger.Infof("结果已保存到：%s\n", c.String("output"))
        }
        
        gologger.Infof("感谢使用 KSubdomain！\n")
        gologger.Printf("\n")
        
        return nil
    },
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}