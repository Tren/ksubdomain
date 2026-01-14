package main

import (
    "bufio"
    "context"
    "os"

    "github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
    "github.com/boy-hack/ksubdomain/v2/pkg/core/options"
    "github.com/boy-hack/ksubdomain/v2/pkg/runner"
    "github.com/boy-hack/ksubdomain/v2/pkg/runner/outputter"
    output2 "github.com/boy-hack/ksubdomain/v2/pkg/runner/outputter/output"
    processbar2 "github.com/boy-hack/ksubdomain/v2/pkg/runner/processbar"
    "github.com/urfave/cli/v2"
)

var verifyCommand = &cli.Command{
    Name:    "verify",
    Aliases: []string{"v"},
    Usage:   "验证模式",
    Flags: append([]cli.Flag{
        &cli.StringFlag{
            Name:     "filename",
            Aliases:  []string{"f"},
            Usage:    "验证域名的文件路径",
            Required: false,
            Value:    "",
        },
    }, CommonFlags...),
    Action: func(c *cli.Context) error {
        if c.NumFlags() == 0 {
            cli.ShowCommandHelpAndExit(c, "verify", 0)
        }
        
        var domains []string
        processBar := &processbar2.ScreenProcess{Silent: c.Bool("silent")}
        
        // 从命令行参数读取域名
        if c.StringSlice("domain") != nil {
            domains = append(domains, c.StringSlice("domain")...)
        }
        
        // 从标准输入读取域名
        if c.Bool("stdin") {
            scanner := bufio.NewScanner(os.Stdin)
            scanner.Split(bufio.ScanLines)
            for scanner.Scan() {
                domains = append(domains, scanner.Text())
            }
        }
        
        // 创建域名通道
        render := make(chan string)
        
        // 读取文件
        go func() {
            // 发送从命令行和stdin读取的域名
            for _, line := range domains {
                render <- line
            }
            
            // 从文件读取域名
            if c.String("filename") != "" {
                f2, err := os.Open(c.String("filename"))
                if err != nil {
                    gologger.Fatalf("打开文件:%s 出现错误:%s\n", c.String("filename"), err.Error())
                }
                defer f2.Close()
                
                iofile := bufio.NewScanner(f2)
                iofile.Split(bufio.ScanLines)
                for iofile.Scan() {
                    render <- iofile.Text()
                }
            }
            close(render)
        }()

        // 配置屏幕输出
        if c.Bool("not-print") {
            processBar = nil
        }
        
        screenWriter, err := output2.NewScreenOutput(c.Bool("silent"))
        if err != nil {
            gologger.Fatalf(err.Error() + "\n")
        }
        
        var writer []outputter.Output
        if !c.Bool("not-print") {
            writer = append(writer, screenWriter)
        }
        
        // 配置文件输出
        if c.String("output") != "" {
            outputFile := c.String("output")
            outputType := c.String("output-type")
            wildFilterMode := c.String("wild-filter-mode")
            
            switch outputType {
            case "txt":
                p, err := output2.NewPlainOutput(outputFile, wildFilterMode)
                if err != nil {
                    gologger.Fatalf(err.Error() + "\n")
                }
                writer = append(writer, p)
            case "json":
                p := output2.NewJsonOutput(outputFile, wildFilterMode)
                writer = append(writer, p)
            case "csv":
                p := output2.NewCsvOutput(outputFile, wildFilterMode)
                writer = append(writer, p)
            default:
                gologger.Fatalf("输出类型错误:%s 暂不支持\n", outputType)
            }
        }
        
        // 配置扫描器
        resolver := options.GetResolvers(c.StringSlice("resolvers"))
        opt := &options.Options{
            Rate:               options.Band2Rate(c.String("band")),
            Domain:             render,
            Resolvers:          resolver,
            Silent:             c.Bool("silent"),
            TimeOut:            c.Int("timeout"),
            Retry:              c.Int("retry"),
            Method:             options.VerifyType,
            Writer:             writer,
            ProcessBar:         processBar,
            EtherInfo:          options.GetDeviceConfig(resolver),
            WildcardFilterMode: c.String("wild-filter-mode"),
            Predict:            c.Bool("predict"),
        }
        
        opt.Check()
        
        // 运行验证
        ctx := context.Background()
        r, err := runner.New(opt)
        if err != nil {
            gologger.Fatalf("%s\n", err.Error())
            return nil
        }
        
        r.RunEnumeration(ctx)
        r.Close()
        return nil
    },
}