package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"
    "encoding/base64"
    
    "github.com/boy-hack/ksubdomain/v2/pkg/core/gologger"
)

// ==================== 统一配置结构 ====================
type AppConfig struct {
    Fofa         *FofaConfig         `json:"fofa,omitempty"`
    VirusTotal   *VirusTotalConfig   `json:"virustotal,omitempty"`
    BinaryEdge   *BinaryEdgeConfig   `json:"binaryedge,omitempty"`
    CertSpotter  *CertSpotterConfig  `json:"certspotter,omitempty"`
}

type FofaConfig struct {
    Enabled bool   `json:"enabled"`
    Email   string `json:"email"`
    Key     string `json:"key"`
    Size    int    `json:"size"`
    Syntax  string `json:"syntax,omitempty"`
}

type VirusTotalConfig struct {
    Enabled bool   `json:"enabled"`
    APIKey  string `json:"api_key"`
}

type BinaryEdgeConfig struct {
    Enabled bool   `json:"enabled"`
    APIKey  string `json:"api_key"`
}

type CertSpotterConfig struct {
    Enabled bool   `json:"enabled"`
    APIKey  string `json:"api_key,omitempty"`
}

// ==================== 配置加载器 ====================
var (
    globalConfig     *AppConfig
    configLoaded     bool
    configLoadError  error
)

func LoadGlobalConfig() (*AppConfig, error) {
    if configLoaded {
        return globalConfig, configLoadError
    }
    
    configPath := "./config.json"
    if _, err := os.Stat(configPath); os.IsNotExist(err) {
        configLoaded = true
        globalConfig = &AppConfig{}
        return globalConfig, nil
    }
    
    data, err := ioutil.ReadFile(configPath)
    if err != nil {
        configLoaded = true
        configLoadError = fmt.Errorf("读取配置文件失败: %v", err)
        gologger.Errorf("%v\n", configLoadError)
        return nil, configLoadError
    }
    
    globalConfig = &AppConfig{}
    if err := json.Unmarshal(data, globalConfig); err != nil {
        configLoaded = true
        configLoadError = fmt.Errorf("解析配置文件失败: %v", err)
        gologger.Errorf("%v\n", configLoadError)
        return nil, configLoadError
    }
    
    configLoaded = true
    return globalConfig, nil
}

// ==================== 数据源接口 ====================
type DomainSource interface {
    GetSubdomains(domain string) ([]string, error)
    Name() string
    IsEnabled() bool
}

type OnlineSources struct {
    sources []DomainSource
}

// ==================== CRTSH数据源 ====================
type CRTSHSource struct{}

func (c *CRTSHSource) Name() string { return "crt.sh" }
func (c *CRTSHSource) IsEnabled() bool { return true }

func (c *CRTSHSource) GetSubdomains(domain string) ([]string, error) {
    url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
    client := &http.Client{Timeout: 30 * time.Second}
    
    resp, err := client.Get(url)
    if err != nil {
        return []string{}, nil
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        return []string{}, nil
    }
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return []string{}, nil
    }
    
    var entries []struct {
        NameValue  string `json:"name_value"`
        CommonName string `json:"common_name"`
    }
    
    if err := json.Unmarshal(body, &entries); err != nil {
        return []string{}, nil
    }
    
    var subdomains []string
    for _, entry := range entries {
        names := strings.Fields(strings.ReplaceAll(entry.NameValue, "\n", " "))
        for _, name := range names {
            cleaned := cleanSubdomain(name, domain)
            if cleaned != "" {
                subdomains = append(subdomains, cleaned)
            }
        }
        
        if entry.CommonName != "" {
            cleaned := cleanSubdomain(entry.CommonName, domain)
            if cleaned != "" {
                subdomains = append(subdomains, cleaned)
            }
        }
    }
    
    uniqueSubdomains := removeDuplicates(subdomains)
    if len(uniqueSubdomains) > 0 {
        gologger.Debugf("[crt.sh] 为 %s 发现 %d 个子域名\n", domain, len(uniqueSubdomains))
    }
    
    return uniqueSubdomains, nil
}

// ==================== RapidDNS数据源 ====================
type RapidDNSSource struct{}

func (r *RapidDNSSource) Name() string { return "rapiddns.io" }
func (r *RapidDNSSource) IsEnabled() bool { return true }

func (r *RapidDNSSource) GetSubdomains(domain string) ([]string, error) {
    url := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", domain)
    client := &http.Client{
        Timeout: 30 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
    
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return []string{}, nil
    }
    req.Header.Set("User-Agent", "Mozilla/5.0")
    
    resp, err := client.Do(req)
    if err != nil {
        return []string{}, nil
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        return []string{}, nil
    }
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return []string{}, nil
    }
    
    content := string(body)
    subdomains := extractSubdomainsFromText(content, domain)
    var cleanedSubdomains []string
    
    for _, subdomain := range subdomains {
        cleaned := cleanSubdomain(subdomain, domain)
        if cleaned != "" {
            cleanedSubdomains = append(cleanedSubdomains, cleaned)
        }
    }
    
    uniqueSubdomains := removeDuplicates(cleanedSubdomains)
    if len(uniqueSubdomains) > 0 {
        gologger.Debugf("[rapiddns.io] 为 %s 发现 %d 个子域名\n", domain, len(uniqueSubdomains))
    }
    
    return uniqueSubdomains, nil
}

// ==================== HackerTarget数据源 ====================
type HackerTargetSource struct{}

func (h *HackerTargetSource) Name() string { return "hackertarget.com" }
func (h *HackerTargetSource) IsEnabled() bool { return true }

func (h *HackerTargetSource) GetSubdomains(domain string) ([]string, error) {
    url := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
    client := &http.Client{Timeout: 30 * time.Second}
    
    resp, err := client.Get(url)
    if err != nil {
        return []string{}, nil
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        return []string{}, nil
    }
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return []string{}, nil
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
            if cleaned != "" && cleaned != "API count exceeded" {
                subdomains = append(subdomains, cleaned)
            }
        }
    }
    
    uniqueSubdomains := removeDuplicates(subdomains)
    if len(uniqueSubdomains) > 0 {
        gologger.Debugf("[hackertarget.com] 为 %s 发现 %d 个子域名\n", domain, len(uniqueSubdomains))
    }
    
    return uniqueSubdomains, nil
}

// ==================== FOFA数据源 ====================
type FOFASource struct {
    config *FofaConfig
}

func (f *FOFASource) Name() string { return "fofa.info" }

func (f *FOFASource) IsEnabled() bool {
    return f.config != nil && f.config.Enabled && f.config.Email != "" && f.config.Key != ""
}

func (f *FOFASource) GetSubdomains(domain string) ([]string, error) {
    if !f.IsEnabled() {
        return []string{}, nil
    }
    
    size := f.config.Size
    if size <= 0 { size = 100 }
    
    syntax := f.config.Syntax
    if syntax == "" { syntax = "domain=\"{domain}\"" }
    
    query := strings.ReplaceAll(syntax, "{domain}", domain)
    encodedQuery := base64.StdEncoding.EncodeToString([]byte(query))
    
    apiURL := fmt.Sprintf(
        "https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=%d&fields=host",
        url.QueryEscape(f.config.Email),
        url.QueryEscape(f.config.Key),
        url.QueryEscape(encodedQuery),
        size,
    )
    
    client := &http.Client{Timeout: 30 * time.Second}
    req, err := http.NewRequest("GET", apiURL, nil)
    if err != nil {
        gologger.Debugf("[FOFA] 请求创建失败: %v\n", err)
        return []string{}, nil
    }
    req.Header.Set("User-Agent", "KSubdomain/1.0")
    
    resp, err := client.Do(req)
    if err != nil {
        gologger.Debugf("[FOFA] API请求失败: %v\n", err)
        return []string{}, nil
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        body, _ := ioutil.ReadAll(resp.Body)
        gologger.Debugf("[FOFA] API错误 %d: %s\n", resp.StatusCode, string(body))
        return []string{}, nil
    }
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        gologger.Debugf("[FOFA] 读取响应失败: %v\n", err)
        return []string{}, nil
    }
    
    var apiResponse struct {
        Error   bool       `json:"error"`
        ErrMsg  string     `json:"errmsg"`
        Results [][]string `json:"results"`
    }
    
    if err := json.Unmarshal(body, &apiResponse); err != nil {
        gologger.Debugf("[FOFA] 解析JSON失败: %v\n", err)
        return []string{}, nil
    }
    
    if apiResponse.Error {
        gologger.Debugf("[FOFA] API返回错误: %s\n", apiResponse.ErrMsg)
        return []string{}, nil
    }
    
    var subdomains []string
    for _, row := range apiResponse.Results {
        if len(row) > 0 {
            host := strings.TrimSpace(row[0])
            cleaned := f.cleanFofaHost(host, domain)
            if cleaned != "" {
                subdomains = append(subdomains, cleaned)
            }
        }
    }
    
    uniqueSubdomains := removeDuplicates(subdomains)
    if len(uniqueSubdomains) > 0 {
        gologger.Infof("[FOFA] 为 %s 发现 %d 个子域名\n", domain, len(uniqueSubdomains))
        
        // 显示前5个作为示例
        showCount := 5
        if len(uniqueSubdomains) < showCount {
            showCount = len(uniqueSubdomains)
        }
        for i := 0; i < showCount; i++ {
            gologger.Printf("  - %s\n", uniqueSubdomains[i])
        }
        if len(uniqueSubdomains) > showCount {
            gologger.Printf("  ... 还有 %d 个子域名\n", len(uniqueSubdomains)-showCount)
        }
    } else {
        gologger.Debugf("[FOFA] 未为 %s 发现子域名\n", domain)
    }
    
    return uniqueSubdomains, nil
}

func (f *FOFASource) cleanFofaHost(host, domain string) string {
    host = strings.TrimPrefix(host, "http://")
    host = strings.TrimPrefix(host, "https://")
    
    if idx := strings.Index(host, ":"); idx != -1 {
        host = host[:idx]
    }
    
    if idx := strings.Index(host, "/"); idx != -1 {
        host = host[:idx]
    }
    
    return cleanSubdomain(host, domain)
}

// ==================== VirusTotal数据源 ====================
type VirusTotalSource struct {
    config *VirusTotalConfig
}

func (v *VirusTotalSource) Name() string { return "virustotal.com" }
func (v *VirusTotalSource) IsEnabled() bool {
    if v.config != nil && v.config.Enabled && v.config.APIKey != "" {
        return true
    }
    return os.Getenv("VIRUSTOTAL_API_KEY") != ""
}

func (v *VirusTotalSource) GetSubdomains(domain string) ([]string, error) {
    apiKey := v.config.APIKey
    if apiKey == "" {
        apiKey = os.Getenv("VIRUSTOTAL_API_KEY")
    }
    
    if apiKey == "" {
        return []string{}, nil
    }
    
    url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=100", domain)
    client := &http.Client{Timeout: 30 * time.Second}
    
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return []string{}, nil
    }
    req.Header.Set("x-apikey", apiKey)
    req.Header.Set("Accept", "application/json")
    
    resp, err := client.Do(req)
    if err != nil {
        return []string{}, nil
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        return []string{}, nil
    }
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return []string{}, nil
    }
    
    var vtResponse struct {
        Data []struct {
            ID   string `json:"id"`
            Type string `json:"type"`
        } `json:"data"`
    }
    
    if err := json.Unmarshal(body, &vtResponse); err != nil {
        return []string{}, nil
    }
    
    var subdomains []string
    for _, item := range vtResponse.Data {
        cleaned := cleanSubdomain(item.ID, domain)
        if cleaned != "" {
            subdomains = append(subdomains, cleaned)
        }
    }
    
    uniqueSubdomains := removeDuplicates(subdomains)
    if len(uniqueSubdomains) > 0 {
        gologger.Debugf("[VirusTotal] 为 %s 发现 %d 个子域名\n", domain, len(uniqueSubdomains))
    }
    
    return uniqueSubdomains, nil
}

// ==================== BinaryEdge数据源 ====================
type BinaryEdgeSource struct {
    config *BinaryEdgeConfig
}

func (b *BinaryEdgeSource) Name() string { return "binaryedge.io" }
func (b *BinaryEdgeSource) IsEnabled() bool {
    if b.config != nil && b.config.Enabled && b.config.APIKey != "" {
        return true
    }
    return os.Getenv("BINARYEDGE_API_KEY") != ""
}

func (b *BinaryEdgeSource) GetSubdomains(domain string) ([]string, error) {
    apiKey := b.config.APIKey
    if apiKey == "" {
        apiKey = os.Getenv("BINARYEDGE_API_KEY")
    }
    
    if apiKey == "" {
        return []string{}, nil
    }
    
    url := fmt.Sprintf("https://api.binaryedge.io/v2/query/domains/subdomain/%s", domain)
    client := &http.Client{Timeout: 60 * time.Second}
    
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return []string{}, nil
    }
    req.Header.Set("X-Key", apiKey)
    req.Header.Set("Accept", "application/json")
    
    resp, err := client.Do(req)
    if err != nil {
        return []string{}, nil
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        return []string{}, nil
    }
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return []string{}, nil
    }
    
    var beResponse struct {
        Events []struct {
            Domain string `json:"domain"`
        } `json:"events"`
    }
    
    if err := json.Unmarshal(body, &beResponse); err != nil {
        return []string{}, nil
    }
    
    var subdomains []string
    for _, event := range beResponse.Events {
        cleaned := cleanSubdomain(event.Domain, domain)
        if cleaned != "" {
            subdomains = append(subdomains, cleaned)
        }
    }
    
    uniqueSubdomains := removeDuplicates(subdomains)
    if len(uniqueSubdomains) > 0 {
        gologger.Debugf("[BinaryEdge] 为 %s 发现 %d 个子域名\n", domain, len(uniqueSubdomains))
    }
    
    return uniqueSubdomains, nil
}

// ==================== CertSpotter数据源 ====================
type CertSpotterSource struct {
    config *CertSpotterConfig
}

func (c *CertSpotterSource) Name() string { return "certspotter.com" }
func (c *CertSpotterSource) IsEnabled() bool {
    return c.config != nil && c.config.Enabled
}

func (c *CertSpotterSource) GetSubdomains(domain string) ([]string, error) {
    apiKey := c.config.APIKey
    baseURL := "https://api.certspotter.com"
    url := fmt.Sprintf("%s/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", baseURL, domain)
    
    if apiKey != "" {
        url = fmt.Sprintf("%s&access_token=%s", url, apiKey)
    }
    
    client := &http.Client{Timeout: 30 * time.Second}
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return []string{}, nil
    }
    
    req.Header.Set("User-Agent", "Mozilla/5.0")
    req.Header.Set("Accept", "application/json")
    
    resp, err := client.Do(req)
    if err != nil {
        return []string{}, nil
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        return []string{}, nil
    }
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return []string{}, nil
    }
    
    var certEntries []struct {
        DNSNames []string `json:"dns_names"`
    }
    
    if err := json.Unmarshal(body, &certEntries); err != nil {
        return []string{}, nil
    }
    
    var subdomains []string
    for _, entry := range certEntries {
        for _, dnsName := range entry.DNSNames {
            cleaned := cleanSubdomain(dnsName, domain)
            if cleaned != "" && !strings.Contains(cleaned, "*") {
                subdomains = append(subdomains, cleaned)
            }
        }
    }
    
    uniqueSubdomains := removeDuplicates(subdomains)
    if len(uniqueSubdomains) > 0 {
        gologger.Debugf("[CertSpotter] 为 %s 发现 %d 个子域名\n", domain, len(uniqueSubdomains))
    }
    
    return uniqueSubdomains, nil
}

// ==================== 辅助函数 ====================
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

func extractSubdomainsFromText(text, domain string) []string {
    escapedDomain := regexp.QuoteMeta(domain)
    pattern := fmt.Sprintf(`([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+%s`, escapedDomain)
    re := regexp.MustCompile(pattern)
    
    matches := re.FindAllString(text, -1)
    var subdomains []string
    for _, match := range matches {
        match = regexp.MustCompile(`^\*\.`).ReplaceAllString(match, "")
        subdomains = append(subdomains, match)
    }
    return subdomains
}

func cleanSubdomain(subdomain, domain string) string {
    subdomain = strings.TrimSpace(subdomain)
    if subdomain == "" {
        return ""
    }
    
    htmlTagPattern := regexp.MustCompile(`<[^>]*>`)
    subdomain = htmlTagPattern.ReplaceAllString(subdomain, "")
    
    charsToTrim := `<>()[]{}"',;:!?|/\`
    subdomain = strings.Trim(subdomain, charsToTrim)
    
    subdomain = regexp.MustCompile(`^\*\.`).ReplaceAllString(subdomain, "")
    
    if !strings.Contains(strings.ToLower(subdomain), strings.ToLower(domain)) {
        return ""
    }
    
    if !isValidSubdomain(subdomain) {
        return ""
    }
    
    return subdomain
}

func isValidSubdomain(subdomain string) bool {
    if strings.HasPrefix(subdomain, ".") || strings.HasSuffix(subdomain, ".") {
        return false
    }
    if strings.Contains(subdomain, "..") {
        return false
    }
    pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
    matched, _ := regexp.MatchString(pattern, subdomain)
    return matched
}

// ==================== 数据源初始化 ====================
func NewOnlineSources() *OnlineSources {
    config, err := LoadGlobalConfig()
    if err != nil {
        gologger.Warningf("配置加载失败，仅启用免费数据源\n")
        return &OnlineSources{
            sources: []DomainSource{
                &CRTSHSource{},
                &RapidDNSSource{},
                &HackerTargetSource{},
            },
        }
    }
    
    sources := []DomainSource{
        &CRTSHSource{},
        &RapidDNSSource{},
        &HackerTargetSource{},
    }
    
    // 按顺序添加其他数据源
    if config.Fofa != nil && config.Fofa.Enabled && config.Fofa.Email != "" && config.Fofa.Key != "" {
        sources = append(sources, &FOFASource{config: config.Fofa})
    }
    
    if config.VirusTotal != nil && config.VirusTotal.Enabled && config.VirusTotal.APIKey != "" {
        sources = append(sources, &VirusTotalSource{config: config.VirusTotal})
    }
    
    if config.BinaryEdge != nil && config.BinaryEdge.Enabled && config.BinaryEdge.APIKey != "" {
        sources = append(sources, &BinaryEdgeSource{config: config.BinaryEdge})
    }
    
    if config.CertSpotter != nil && config.CertSpotter.Enabled {
        sources = append(sources, &CertSpotterSource{config: config.CertSpotter})
    }
    
    return &OnlineSources{sources: sources}
}

// ==================== OnlineSubdomainFinder ====================
type OnlineSubdomainFinder struct {
    sources *OnlineSources
}

func NewOnlineSubdomainFinder() *OnlineSubdomainFinder {
    return &OnlineSubdomainFinder{
        sources: NewOnlineSources(),
    }
}

func (f *OnlineSubdomainFinder) FindSubdomains(domains []string) map[string][]string {
    result := make(map[string][]string)
    
    for i, domain := range domains {
        gologger.Infof("正在从在线源查询 %s 的子域名...\n", domain)
        
        var allSubdomains []string
        var mu sync.Mutex
        var wg sync.WaitGroup
        
        // 用于统计每个源的贡献
        sourceStats := make(map[string]int)
        
        for _, source := range f.sources.sources {
            if !source.IsEnabled() {
                continue
            }
            
            wg.Add(1)
            go func(s DomainSource) {
                defer wg.Done()
                
                subdomains, err := s.GetSubdomains(domain)
                if err != nil {
                    gologger.Debugf("%s 查询失败: %v\n", s.Name(), err)
                    return
                }
                
                mu.Lock()
                allSubdomains = append(allSubdomains, subdomains...)
                sourceStats[s.Name()] = len(subdomains)
                mu.Unlock()
            }(source)
        }
        
        wg.Wait()
        
        uniqueSubdomains := removeDuplicates(allSubdomains)
        
        if len(uniqueSubdomains) > 0 {
            result[domain] = uniqueSubdomains
            
            // 显示每个源的统计
            statsStrings := []string{}
            totalFound := 0
            for sourceName, count := range sourceStats {
                if count > 0 {
                    statsStrings = append(statsStrings, fmt.Sprintf("%s:%d", sourceName, count))
                    totalFound += count
                }
            }
            
            gologger.Infof("为 %s 找到 %d 个子域名 (来自 %d 个数据源: %s)\n", 
                domain, len(uniqueSubdomains), len(statsStrings), strings.Join(statsStrings, ", "))
        } else {
            gologger.Infof("%s: 未发现子域名\n", domain)
        }
        
        // 避免请求过快
        if i < len(domains)-1 {
            time.Sleep(500 * time.Millisecond)
        }
    }
    
    return result
}