// cmd/ksubdomain/common.go
package main

import "github.com/urfave/cli/v2"

var CommonFlags = []cli.Flag{
    &cli.StringSliceFlag{
        Name:    "domain",
        Aliases: []string{"d"},
        Usage:   "域名",
    },
    &cli.BoolFlag{
        Name:    "stdin",
        Usage:   "从标准输入读取",
        Value:   false,
    },
    &cli.StringFlag{
        Name:    "resolvers",
        Aliases: []string{"r"},
        Usage:   "DNS解析器列表文件",
        Value:   "",
    },
    &cli.StringFlag{
        Name:    "band",
        Aliases: []string{"b"},
        Usage:   "带宽控制，如 2M,500k",
        Value:   "2M",
    },
    &cli.IntFlag{
        Name:    "retry",
        Usage:   "重试次数",
        Value:   3,
    },
    &cli.IntFlag{
        Name:    "timeout",
        Usage:   "超时时间(秒)",
        Value:   6,
    },
    &cli.StringFlag{
        Name:    "output",
        Aliases: []string{"o"},
        Usage:   "输出文件路径",
        Value:   "",
    },
    &cli.StringFlag{
        Name:    "output-type",
        Aliases: []string{"ot"},
        Usage:   "输出类型: txt, json, csv",
        Value:   "txt",
    },
    &cli.BoolFlag{
        Name:    "silent",
        Usage:   "静默模式",
        Value:   false,
    },
    &cli.BoolFlag{
        Name:    "not-print",
        Aliases: []string{"np"},
        Usage:   "不打印结果到屏幕",
        Value:   false,
    },
    &cli.StringFlag{
        Name:    "wild-filter-mode",
        Usage:   "泛解析过滤模式: none, local, remote",
        Value:   "local",
    },
    &cli.BoolFlag{
        Name:    "predict",
        Usage:   "启用预测模式",
        Value:   false,
    },
    &cli.StringFlag{
        Name:    "eth",
        Aliases: []string{"e"},
        Usage:   "指定网卡名称",
    },
}