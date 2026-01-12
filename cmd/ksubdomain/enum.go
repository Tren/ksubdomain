package main

import (
	"bufio"
	"context"
	"math/rand"
	"os"

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

var enumCommand = &cli.Command{
	Name:    string(options.EnumType),
	Aliases: []string{"e"},
	Usage:   "枚举域名",
	Flags: append(commonFlags, []cli.Flag{
		&cli.StringFlag{
			Name:     "filename",
			Aliases:  []string{"f"},
			Usage:    "字典路径",
			Required: false,
			Value:    "",
		},
		&cli.BoolFlag{
			Name:  "ns",
			Usage: "读取域名ns记录并加入到ns解析器中",
			Value: false,
		},
		&cli.StringFlag{
			Name:    "domain-list",
			Aliases: []string{"ds"},
			Usage:   "指定域名列表文件",
			Value:   "",
		},
		&cli.BoolFlag{
			Name:  "online-only",
			Usage: "仅使用在线源获取的子域名，不结合字典",
			Value: false,
		},
		&cli.BoolFlag{
			Name:  "no-online",
			Usage: "禁用在线子域名查询",
			Value: false,
		},
	}...),
	Action: func(c *cli.Context) error {
		if c.NumFlags() == 0 {
			cli.ShowCommandHelpAndExit(c, "enum", 0)
		}
		var domains []string
		processBar := &processbar2.ScreenProcess{Silent: c.Bool("silent")}

		// handle domain
		if c.StringSlice("domain") != nil {
			domains = append(domains, c.StringSlice("domain")...)
		}
		if c.Bool("stdin") {
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Split(bufio.ScanLines)
			for scanner.Scan() {
				domains = append(domains, scanner.Text())
			}
		}
		if c.String("domain-list") != "" {
			filename := c.String("domain-list")
			f, err := os.Open(filename)
			if err != nil {
				gologger.Fatalf("打开文件:%s 出现错误:%s", filename, err.Error())
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Split(bufio.ScanLines)
			for scanner.Scan() {
				domain := scanner.Text()
				domains = append(domains, domain)
			}
		}

		// 验证域名列表不为空
		if len(domains) == 0 {
			gologger.Fatalf("未指定要枚举的域名")
		}

		wildIPS := make([]string, 0)
		if c.String("wild-filter-mode") != "none" {
			for _, sub := range domains {
				ok, ips := runner.IsWildCard(sub)
				if ok {
					wildIPS = append(wildIPS, ips...)
					gologger.Infof("发现泛解析域名:%s", sub)
				}
			}
		}

		// 从在线源获取子域名
		onlineSubdomains := make(map[string][]string)
		if !c.Bool("no-online") {
			finder := NewOnlineSubdomainFinder()
			onlineSubdomains = finder.FindSubdomains(domains)
		}

		render := make(chan string, 1000) // 增加缓冲区大小提高性能
		go func() {
			defer close(render)
			
			// 使用集合去重
			sentSubdomains := make(map[string]bool)
			
			// 首先发送从在线源获取的子域名
			for _, subdomains := range onlineSubdomains {
				for _, subdomain := range subdomains {
					if !sentSubdomains[subdomain] {
						sentSubdomains[subdomain] = true
						render <- subdomain
					}
				}
			}
			
			// 如果设置了 --online-only，则跳过字典枚举
			if c.Bool("online-only") {
				gologger.Infof("仅使用在线源子域名，跳过字典枚举")
				return
			}
			
			filename := c.String("filename")
			if filename == "" {
				subdomainDict := core2.GetDefaultSubdomainData()
				for _, domain := range domains {
					for _, sub := range subdomainDict {
						dd := sub + "." + domain
						// 检查是否已从在线源发送过
						if !sentSubdomains[dd] {
							sentSubdomains[dd] = true
							render <- dd
						}
					}
				}
			} else {
				f2, err := os.Open(filename)
				if err != nil {
					gologger.Fatalf("打开文件:%s 出现错误:%s", c.String("filename"), err.Error())
				}
				defer f2.Close()
				iofile := bufio.NewScanner(f2)
				iofile.Split(bufio.ScanLines)
				for iofile.Scan() {
					sub := iofile.Text()
					for _, domain := range domains {
						dd := sub + "." + domain
						// 检查是否已从在线源发送过
						if !sentSubdomains[dd] {
							sentSubdomains[dd] = true
							render <- dd
						}
					}
				}
			}
		}()
		
		// 取域名的dns,加入到resolver中
		specialDns := make(map[string][]string)
		defaultResolver := options.GetResolvers(c.StringSlice("resolvers"))
		if c.Bool("ns") {
			for _, domain := range domains {
				nsServers, ips, err := ns.LookupNS(domain, defaultResolver[rand.Intn(len(defaultResolver))])
				if err != nil {
					continue
				}
				specialDns[domain] = ips
				gologger.Infof("%s ns:%v", domain, nsServers)
			}
		}
		
		if c.Bool("not-print") {
			processBar = nil
		}

		screenWriter, err := output2.NewScreenOutput(c.Bool("silent"))
		if err != nil {
			gologger.Fatalf(err.Error())
		}
		var writer []outputter.Output
		if !c.Bool("not-print") {
			writer = append(writer, screenWriter)
		}
		if c.String("output") != "" {
			outputFile := c.String("output")
			outputType := c.String("output-type")
			wildFilterMode := c.String("wild-filter-mode")
			switch outputType {
			case "txt":
				p, err := output2.NewPlainOutput(outputFile, wildFilterMode)
				if err != nil {
					gologger.Fatalf(err.Error())
				}
				writer = append(writer, p)
			case "json":
				p := output2.NewJsonOutput(outputFile, wildFilterMode)
				writer = append(writer, p)
			case "csv":
				p := output2.NewCsvOutput(outputFile, wildFilterMode)
				writer = append(writer, p)
			default:
				gologger.Fatalf("输出类型错误:%s 暂不支持", outputType)
			}
		}
		
		opt := &options.Options{
			Rate:               options.Band2Rate(c.String("band")),
			Domain:             render,
			Resolvers:          defaultResolver,
			Silent:             c.Bool("silent"),
			TimeOut:            c.Int("timeout"),
			Retry:              c.Int("retry"),
			Method:             options.VerifyType,
			Writer:             writer,
			ProcessBar:         processBar,
			SpecialResolvers:   specialDns,
			WildcardFilterMode: c.String("wild-filter-mode"),
			WildIps:            wildIPS,
			Predict:            c.Bool("predict"),
		}
		opt.Check()
		opt.EtherInfo = options.GetDeviceConfig(defaultResolver)
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