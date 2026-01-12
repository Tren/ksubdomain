package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
)

// DomainSource 定义子域名查询源接口
type DomainSource interface {
	GetSubdomains(domain string) ([]string, error)
	Name() string
}

// OnlineSources 管理所有在线查询源
type OnlineSources struct {
	sources []DomainSource
}

// NewOnlineSources 创建在线查询源管理器
func NewOnlineSources() *OnlineSources {
	return &OnlineSources{
		sources: []DomainSource{
			&CRTSHSource{},
			&RapidDNSSource{},
			&HackerTargetSource{},
		},
	}
}

// GetAllSubdomains 从所有源获取子域名
func (o *OnlineSources) GetAllSubdomains(domain string) ([]string, error) {
	var allSubdomains []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	errors := make([]error, 0)

	for _, source := range o.sources {
		wg.Add(1)
		go func(s DomainSource) {
			defer wg.Done()

			gologger.Debugf("正在从 %s 查询 %s 的子域名...", s.Name(), domain)
			
			subdomains, err := s.GetSubdomains(domain)
			if err != nil {
				gologger.Warningf("%s 查询失败: %v", s.Name(), err)
				mu.Lock()
				errors = append(errors, err)
				mu.Unlock()
				return
			}

			mu.Lock()
			allSubdomains = append(allSubdomains, subdomains...)
			mu.Unlock()
			
			gologger.Debugf("从 %s 获取到 %d 个子域名", s.Name(), len(subdomains))
		}(source)

		// 避免请求过快被限制
		time.Sleep(500 * time.Millisecond)
	}

	wg.Wait()
	
	// 去重
	uniqueSubdomains := make(map[string]bool)
	var result []string
	
	for _, subdomain := range allSubdomains {
		subdomain = strings.TrimSpace(subdomain)
		if subdomain == "" {
			continue
		}
		
		if !uniqueSubdomains[subdomain] {
			uniqueSubdomains[subdomain] = true
			result = append(result, subdomain)
		}
	}

	return result, nil
}

// 辅助函数：从文本中提取子域名
func extractSubdomainsFromText(text, domain string) []string {
	var subdomains []string
	
	// 将域名转义以便在正则表达式中使用
	escapedDomain := regexp.QuoteMeta(domain)
	
	// 匹配子域名的正则表达式
	pattern := fmt.Sprintf(`([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+%s`, escapedDomain)
	re := regexp.MustCompile(pattern)
	
	matches := re.FindAllString(text, -1)
	for _, match := range matches {
		// 移除可能的通配符
		match = regexp.MustCompile(`^\*\.`).ReplaceAllString(match, "")
		subdomains = append(subdomains, match)
	}
	
	return subdomains
}

// 辅助函数：去除重复项
func removeDuplicates(items []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

// 辅助函数：清理子域名字符串，去除HTML标签等
func cleanSubdomain(subdomain, domain string) string {
	// 去除前后空白
	subdomain = strings.TrimSpace(subdomain)
	if subdomain == "" {
		return ""
	}
	
	// 去除HTML标签
	htmlTagPattern := regexp.MustCompile(`<[^>]*>`)
	subdomain = htmlTagPattern.ReplaceAllString(subdomain, "")
	
	// 去除常见的分隔符和特殊字符
	charsToTrim := `<>()[]{}"'` + "`" + `,;:!?|/\\`
	subdomain = strings.Trim(subdomain, charsToTrim)
	
	// 去除可能的通配符
	subdomain = regexp.MustCompile(`^\*\.`).ReplaceAllString(subdomain, "")
	
	// 确保包含目标域名（不区分大小写）
	if !strings.Contains(strings.ToLower(subdomain), strings.ToLower(domain)) {
		return ""
	}
	
	// 验证域名格式
	if !isValidSubdomain(subdomain) {
		return ""
	}
	
	return subdomain
}

// 辅助函数：验证子域名格式
func isValidSubdomain(subdomain string) bool {
	// 子域名不能以点开头或结尾
	if strings.HasPrefix(subdomain, ".") || strings.HasSuffix(subdomain, ".") {
		return false
	}
	
	// 不能有连续的句点
	if strings.Contains(subdomain, "..") {
		return false
	}
	
	// 匹配有效的子域名格式
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, subdomain)
	return matched
}

// CRTSHSource crt.sh 证书透明度查询
type CRTSHSource struct{}

func (c *CRTSHSource) Name() string {
	return "crt.sh"
}

func (c *CRTSHSource) GetSubdomains(domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("状态码: %d", resp.StatusCode)
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}
	
	var crtEntries []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	
	err = json.Unmarshal(body, &crtEntries)
	if err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v", err)
	}
	
	var subdomains []string
	
	for _, entry := range crtEntries {
		// 处理name_value字段
		names := strings.Fields(strings.ReplaceAll(entry.NameValue, "\n", " "))
		for _, name := range names {
			cleaned := cleanSubdomain(name, domain)
			if cleaned != "" {
				subdomains = append(subdomains, cleaned)
			}
		}
		
		// 处理common_name字段
		if entry.CommonName != "" {
			cleaned := cleanSubdomain(entry.CommonName, domain)
			if cleaned != "" {
				subdomains = append(subdomains, cleaned)
			}
		}
	}
	
	return removeDuplicates(subdomains), nil
}

// RapidDNSSource RapidDNS查询
type RapidDNSSource struct{}

func (r *RapidDNSSource) Name() string {
	return "rapiddns.io"
}

func (r *RapidDNSSource) GetSubdomains(domain string) ([]string, error) {
	url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1&down=1", domain)
	
	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}
	
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("状态码: %d", resp.StatusCode)
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}
	
	content := string(body)
	
	// 使用正则表达式提取子域名
	subdomains := extractSubdomainsFromText(content, domain)
	
	// 清理每个子域名
	var cleanedSubdomains []string
	for _, subdomain := range subdomains {
		cleaned := cleanSubdomain(subdomain, domain)
		if cleaned != "" {
			cleanedSubdomains = append(cleanedSubdomains, cleaned)
		}
	}
	
	return removeDuplicates(cleanedSubdomains), nil
}

// HackerTargetSource HackerTarget查询
type HackerTargetSource struct{}

func (h *HackerTargetSource) Name() string {
	return "hackertarget.com"
}

func (h *HackerTargetSource) GetSubdomains(domain string) ([]string, error) {
	url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("状态码: %d", resp.StatusCode)
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}
	
	content := string(body)
	var subdomains []string
	
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "error") || strings.Contains(line, "API limit") {
			continue
		}
		
		parts := strings.Split(line, ",")
		if len(parts) > 0 {
			cleaned := cleanSubdomain(strings.TrimSpace(parts[0]), domain)
			if cleaned != "" && cleaned != "API count exceeded" && cleaned != "error" {
				subdomains = append(subdomains, cleaned)
			}
		}
	}
	
	return removeDuplicates(subdomains), nil
}

// OnlineSubdomainFinder 在线子域名查找器
type OnlineSubdomainFinder struct {
	sources *OnlineSources
}

// NewOnlineSubdomainFinder 创建在线子域名查找器
func NewOnlineSubdomainFinder() *OnlineSubdomainFinder {
	return &OnlineSubdomainFinder{
		sources: NewOnlineSources(),
	}
}

// FindSubdomains 查找子域名
func (f *OnlineSubdomainFinder) FindSubdomains(domains []string) map[string][]string {
	result := make(map[string][]string)
	
	for i, domain := range domains {
		gologger.Infof("正在从在线源查询 %s 的子域名...", domain)
		
		subdomains, err := f.sources.GetAllSubdomains(domain)
		if err != nil {
			gologger.Errorf("查询 %s 的在线子域名失败: %v", domain, err)
			continue
		}
		
		if len(subdomains) > 0 {
			result[domain] = subdomains
			gologger.Infof("为 %s 从在线源找到 %d 个子域名", domain, len(subdomains))
		} else {
			gologger.Warningf("未从在线源找到 %s 的子域名", domain)
		}
		
		// 避免请求过快
		if i < len(domains)-1 {
			time.Sleep(1 * time.Second)
		}
	}
	
	return result
}
