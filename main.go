package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mrvcoder/V2rayCollector/collector"

	"github.com/PuerkitoBio/goquery"
	"github.com/jszwec/csvutil"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	clientTransport        *http.Transport
	client                 *http.Client
	proxyMu                sync.RWMutex
	currentProxyURL        *url.URL
	defaultMessagesToCheck = 600
	ConfigsNames           = "جوین بدی، وصل میشی @VaslMishi"
	configs                = map[string]string{
		"ss":     "",
		"vmess":  "",
		"trojan": "",
		"vless":  "",
		"mixed":  "",
	}
	ConfigFileIds = map[string]int32{
		"ss":     0,
		"vmess":  0,
		"trojan": 0,
		"vless":  0,
		"mixed":  0,
	}
	myregex = map[string]string{
		"ss":     `(?m)(...ss:|^ss:)\/\/.+?(%3A%40|#)`,
		"vmess":  `(?m)vmess:\/\/.+`,
		"trojan": `(?m)trojan:\/\/.+?(%3A%40|#)`,
		"vless":  `(?m)vless:\/\/.+?(%3A%40|#)`,
	}
	sort                   = flag.Bool("sort", true, "sort from latest to oldest (default: true). Disable with -sort=false")
	nekorayEnabled         = flag.Bool("nekoray", true, "export configs into NekoRay profiles dir if available (use -nekoray=false to disable)")
	nekorayProfiles        = flag.String("nekoray-profiles", "", "path to NekoRay profiles directory (optional)")
	nekorayGroupID         = flag.Int("nekoray-group", 0, "NekoRay group id (default: 0)")
	nekorayInputFile       = flag.String("nekoray-input", "mixed_iran.txt", "input file to import into NekoRay (default: mixed_iran.txt)")
	nekorayURLTest         = flag.Bool("nekoray-urltest", true, "run NekoRay-like URL Test for imported profiles and sort group by lowest latency")
	nekorayURLTestAll      = flag.Bool("nekoray-urltest-all", false, "URL test all profiles in the group (can be slow)")
	nekorayTestURL         = flag.String("nekoray-test-url", "", "override URL used for URL test (default from NekoRay settings)")
	nekorayTestTimeoutSec  = flag.Int("nekoray-test-timeout", 0, "URL test timeout in seconds (default from NekoRay settings)")
	nekorayTestConcurrency = flag.Int("nekoray-test-concurrency", 0, "URL test concurrency (default from NekoRay settings)")
	nekorayAutoProxy       = flag.Bool("nekoray-autoproxy", true, "if Telegram is unreachable, auto-start a local proxy using NekoRay profiles and retry")
	nekorayAutoProxySystem = flag.Bool("nekoray-autoproxy-system-proxy", true, "enable Windows System Proxy while auto proxy is active (Windows only)")
	nekorayAutoProxyKeep   = flag.Bool("nekoray-autoproxy-keep", false, "keep the proxy running and keep system proxy enabled after the program exits")
	nekorayAutoProxyVerify = flag.String("nekoray-autoproxy-verify", "", "override verify URL used to check Telegram connectivity (default: the failing channel URL)")
	httpTimeoutSec         = flag.Int("http-timeout", 30, "HTTP request timeout in seconds (default: 30)")
)

type ChannelsType struct {
	URL          string `csv:"URL"`
	LastMessages int    `csv:"LastMessages"`
}

var (
	autoProxyMu    sync.Mutex
	autoProxyTried bool
	autoProxyStop  func() error
)

func initHTTPClient() {
	clientTransport = http.DefaultTransport.(*http.Transport).Clone()
	clientTransport.Proxy = func(req *http.Request) (*url.URL, error) {
		proxyMu.RLock()
		u := currentProxyURL
		proxyMu.RUnlock()
		return u, nil
	}
	client = &http.Client{Transport: clientTransport}
}

func setClientProxy(proxy string) error {
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		proxyMu.Lock()
		currentProxyURL = nil
		proxyMu.Unlock()
		return nil
	}
	if !strings.Contains(proxy, "://") {
		proxy = "http://" + proxy
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return err
	}
	proxyMu.Lock()
	currentProxyURL = u
	proxyMu.Unlock()
	return nil
}

func ensureTelegramProxy(failingURL string) error {
	if !*nekorayAutoProxy {
		return errors.New("nekoray-autoproxy is disabled")
	}

	autoProxyMu.Lock()
	defer autoProxyMu.Unlock()

	if autoProxyStop != nil {
		return nil
	}
	if autoProxyTried {
		return errors.New("auto proxy already attempted and failed")
	}
	autoProxyTried = true

	profilesDir := strings.TrimSpace(*nekorayProfiles)
	if profilesDir == "" {
		if cwd, err := os.Getwd(); err == nil {
			if dir, err := collector.FindNekoRayProfilesDir(cwd); err == nil && dir != "" {
				profilesDir = dir
			}
		}
	}

	verifyURL := strings.TrimSpace(*nekorayAutoProxyVerify)
	if verifyURL == "" {
		verifyURL = failingURL
	}

	timeout := time.Duration(0)
	if *nekorayTestTimeoutSec > 0 {
		timeout = time.Duration(*nekorayTestTimeoutSec) * time.Second
	} else {
		// Auto-proxy should be fast by default (many users have hundreds of profiles).
		timeout = 8 * time.Second
	}
	concurrency := *nekorayTestConcurrency
	if concurrency <= 0 {
		concurrency = 20
	}

	gologger.Info().Msg("Telegram unreachable, trying NekoRay auto-proxy...")
	res, err := collector.EnsureNekoRayProxyForURL(collector.NekoRayAutoProxyOptions{
		ProfilesDir:       profilesDir,
		GroupID:           *nekorayGroupID,
		VerifyURL:         verifyURL,
		URLTest:           true,
		URLTestURL:        strings.TrimSpace(*nekorayTestURL),
		URLTestTimeout:    timeout,
		URLTestConcurrent: concurrency,
		EnableSystemProxy: *nekorayAutoProxySystem,
		KeepProxyRunning:  *nekorayAutoProxyKeep,
		CoreStartTimeout:  12 * time.Second,
		VerifyTimeout:     15 * time.Second,
		Logf: func(format string, args ...any) {
			gologger.Info().Msg(fmt.Sprintf(format, args...))
		},
	})
	if err != nil {
		return err
	}

	if err := setClientProxy(res.ProxyURL); err != nil {
		return err
	}

	autoProxyStop = res.Stop
	gologger.Info().Msg(fmt.Sprintf("Auto proxy enabled via NekoRay profile id=%d proxy=%s", res.ProfileID, res.ProxyURL))
	return nil
}

func installInterruptHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		gologger.Info().Msg("Interrupted, cleaning up...")

		autoProxyMu.Lock()
		stop := autoProxyStop
		autoProxyMu.Unlock()
		if stop != nil {
			_ = stop()
		}

		os.Exit(130)
	}()
}

func disableProxyForURLTest() (restore func()) {
	prevHTTPProxy := os.Getenv("HTTP_PROXY")
	prevHTTPSProxy := os.Getenv("HTTPS_PROXY")

	restoreEnv := func() {
		if prevHTTPProxy == "" {
			_ = os.Unsetenv("HTTP_PROXY")
		} else {
			_ = os.Setenv("HTTP_PROXY", prevHTTPProxy)
		}
		if prevHTTPSProxy == "" {
			_ = os.Unsetenv("HTTPS_PROXY")
		} else {
			_ = os.Setenv("HTTPS_PROXY", prevHTTPSProxy)
		}
	}

	_ = os.Unsetenv("HTTP_PROXY")
	_ = os.Unsetenv("HTTPS_PROXY")

	var restoreSystemProxy func() error
	if snap, err := collector.GetSystemProxySnapshot(); err == nil && snap.Enabled {
		restore, err := collector.DisableSystemProxy()
		if err == nil {
			restoreSystemProxy = restore
			gologger.Info().Msg("System Proxy temporarily disabled for URL test")
		} else {
			gologger.Error().Msg("Failed to disable System Proxy for URL test: " + err.Error())
		}
	}

	return func() {
		restoreEnv()
		if restoreSystemProxy != nil {
			_ = restoreSystemProxy()
		}
	}
}

func main() {

	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	flag.Parse()
	initHTTPClient()
	installInterruptHandler()
	if *httpTimeoutSec > 0 {
		client.Timeout = time.Duration(*httpTimeoutSec) * time.Second
	}
	defer func() {
		autoProxyMu.Lock()
		stop := autoProxyStop
		autoProxyMu.Unlock()
		if stop != nil {
			_ = stop()
		}
	}()

	// If the user already provided a proxy via env vars, use it for this process too.
	if p := strings.TrimSpace(os.Getenv("HTTP_PROXY")); p != "" {
		_ = setClientProxy(p)
	} else if p := strings.TrimSpace(os.Getenv("HTTPS_PROXY")); p != "" {
		_ = setClientProxy(p)
	}

	// Go does not automatically use Windows System Proxy settings; if a system proxy is enabled,
	// set it for this process too.
	if os.Getenv("HTTP_PROXY") == "" && os.Getenv("HTTPS_PROXY") == "" {
		if snap, err := collector.GetSystemProxySnapshot(); err == nil {
			if proxy, ok := collector.SystemProxyHTTPProxyURL(snap); ok {
				_ = os.Setenv("HTTP_PROXY", proxy)
				_ = os.Setenv("HTTPS_PROXY", proxy)
				_ = setClientProxy(proxy)
				gologger.Info().Msg("Using System Proxy: " + proxy)
			}
		}
	}

	fileData, err := collector.ReadFileContent("channels.csv")
	var channels []ChannelsType
	if err = csvutil.Unmarshal([]byte(fileData), &channels); err != nil {
		gologger.Fatal().Msg("error: " + err.Error())
	}

	// loop through the channels lists
	for _, channel := range channels {

		// change url
		channel.URL = collector.ChangeUrlToTelegramWebUrl(channel.URL)

		// get channel messages
		gologger.Info().Msg("Fetching " + channel.URL)
		resp, err := HttpRequest(channel.URL)
		if err != nil {
			gologger.Error().Msg("Failed to fetch " + channel.URL + ": " + err.Error())
			continue
		}
		doc, err := goquery.NewDocumentFromReader(resp.Body)
		_ = resp.Body.Close()

		if err != nil {
			gologger.Error().Msg("Failed to parse " + channel.URL + ": " + err.Error())
			continue
		}

		fmt.Println(" ")
		fmt.Println(" ")
		fmt.Println("---------------------------------------")
		messagesToCheck := channel.LastMessages
		if messagesToCheck <= 0 {
			messagesToCheck = defaultMessagesToCheck
		}
		gologger.Info().Msg(fmt.Sprintf("Crawling %s (last %d messages)", channel.URL, messagesToCheck))
		CrawlForV2ray(doc, channel.URL, messagesToCheck)
		gologger.Info().Msg("Crawled " + channel.URL + " ! ")
		fmt.Println("---------------------------------------")
		fmt.Println(" ")
		fmt.Println(" ")
	}

	gologger.Info().Msg("Creating output files !")

	for proto, configcontent := range configs {
		lines := collector.RemoveDuplicate(configcontent)
		lines = AddConfigNames(lines, proto)
		linesArr := strings.Split(lines, "\n")
		if *sort {
			// from latest to oldest
			linesArr = collector.Reverse(linesArr)
		}
		lines = strings.Join(linesArr, "\n")
		lines = strings.TrimSpace(lines)
		collector.WriteToFile(lines, proto+"_iran.txt")

	}

	gologger.Info().Msg("All Done :D")

	if *nekorayEnabled {
		profilesDir := strings.TrimSpace(*nekorayProfiles)
		if profilesDir == "" {
			if cwd, err := os.Getwd(); err == nil {
				if dir, err := collector.FindNekoRayProfilesDir(cwd); err == nil && dir != "" {
					profilesDir = dir
				}
			}
		}

		if profilesDir != "" {
			addedIDs, skipped, err := collector.ExportMixedToNekoRayProfiles(*nekorayInputFile, profilesDir, *nekorayGroupID)
			if err != nil {
				gologger.Error().Msg("NekoRay export failed: " + err.Error())
			} else if len(addedIDs) > 0 || skipped > 0 {
				gologger.Info().Msg(fmt.Sprintf("NekoRay export: added=%d skipped=%d dir=%s", len(addedIDs), skipped, profilesDir))
			}

			if *nekorayURLTest {
				restoreProxy := disableProxyForURLTest()
				defer restoreProxy()

				onlyIDs := addedIDs
				if *nekorayURLTestAll {
					onlyIDs = nil
				}
				timeout := time.Duration(0)
				if *nekorayTestTimeoutSec > 0 {
					timeout = time.Duration(*nekorayTestTimeoutSec) * time.Second
				}
				tested, ok, err := collector.NekoRayURLTestAndSort(collector.NekoRayURLTestOptions{
					ProfilesDir: profilesDir,
					GroupID:     *nekorayGroupID,
					OnlyIDs:     onlyIDs,
					TestURL:     strings.TrimSpace(*nekorayTestURL),
					Timeout:     timeout,
					Concurrency: *nekorayTestConcurrency,
					UpdateOrder: true,
				})
				if err != nil {
					gologger.Error().Msg("NekoRay URL test failed: " + err.Error())
				} else {
					if tested > 0 {
						gologger.Info().Msg(fmt.Sprintf("NekoRay URL test: tested=%d ok=%d", tested, ok))
					}
				}
			}

			okTotal, err := collector.NekoRayCountOKProfiles(profilesDir, *nekorayGroupID)
			if err != nil {
				gologger.Error().Msg("NekoRay count ok failed: " + err.Error())
			} else {
				if okTotal > 10 {
					removed, err := collector.NekoRayRemoveUnavailableProfiles(profilesDir, *nekorayGroupID)
					if err != nil {
						gologger.Error().Msg("NekoRay remove unavailable failed: " + err.Error())
					} else if removed > 0 {
						gologger.Info().Msg(fmt.Sprintf("NekoRay remove unavailable: removed=%d", removed))
					}
				}

				if okTotal > 0 {
					verifyURL := strings.TrimSpace(*nekorayAutoProxyVerify)
					if verifyURL == "" && len(channels) > 0 {
						verifyURL = collector.ChangeUrlToTelegramWebUrl(strings.TrimSpace(channels[0].URL))
					}
					if verifyURL == "" {
						verifyURL = "http://cp.cloudflare.com/"
					}

					// Stop any temporary auto-proxy we started for crawling Telegram, then connect
					// to the best (lowest ping) profile and keep it running with System Proxy enabled.
					autoProxyMu.Lock()
					prevStop := autoProxyStop
					autoProxyStop = nil
					autoProxyMu.Unlock()
					if prevStop != nil {
						_ = prevStop()
					}

					res, err := collector.EnsureNekoRayProxyForURL(collector.NekoRayAutoProxyOptions{
						ProfilesDir:       profilesDir,
						GroupID:           *nekorayGroupID,
						VerifyURL:         verifyURL,
						URLTest:           false,
						EnableSystemProxy: true,
						KeepProxyRunning:  true,
						CoreStartTimeout:  12 * time.Second,
						VerifyTimeout:     15 * time.Second,
						Logf: func(format string, args ...any) {
							gologger.Info().Msg(fmt.Sprintf(format, args...))
						},
					})
					if err != nil {
						gologger.Error().Msg("NekoRay final connect failed: " + err.Error())
					} else {
						autoProxyMu.Lock()
						autoProxyStop = res.Stop
						autoProxyMu.Unlock()
						gologger.Info().Msg(fmt.Sprintf("System Proxy enabled via best profile id=%d proxy=%s", res.ProfileID, res.ProxyURL))
					}
				} else {
					gologger.Info().Msg("NekoRay: no OK profiles found; skipping final connect")
				}
			}
		}
	}

}

func AddConfigNames(config string, configtype string) string {
	configs := strings.Split(config, "\n")
	newConfigs := ""
	for protoRegex, regexValue := range myregex {

		for _, extractedConfig := range configs {

			re := regexp.MustCompile(regexValue)
			matches := re.FindStringSubmatch(extractedConfig)
			if len(matches) > 0 {
				extractedConfig = strings.ReplaceAll(extractedConfig, " ", "")
				if extractedConfig != "" {
					if protoRegex == "vmess" {
						extractedConfig = EditVmessPs(extractedConfig, configtype, true)
						if extractedConfig != "" {
							newConfigs += extractedConfig + "\n"
						}
					} else if protoRegex == "ss" {
						Prefix := strings.Split(matches[0], "ss://")[0]
						if Prefix == "" {
							ConfigFileIds[configtype] += 1
							newConfigs += extractedConfig + ConfigsNames + " - " + strconv.Itoa(int(ConfigFileIds[configtype])) + "\n"
						}
					} else {

						ConfigFileIds[configtype] += 1
						newConfigs += extractedConfig + ConfigsNames + " - " + strconv.Itoa(int(ConfigFileIds[configtype])) + "\n"
					}
				}
			}

		}
	}
	return newConfigs
}

func CrawlForV2ray(doc *goquery.Document, channelLink string, messagesToCheck int) {
	// here we are updating our DOM to include the x messages
	// in our DOM and then extract the messages from that DOM
	messages := doc.Find(".tgme_widget_message_wrap").Length()
	link, exist := doc.Find(".tgme_widget_message_wrap .js-widget_message").Last().Attr("data-post")

	if messages < messagesToCheck && exist {
		number := strings.Split(link, "/")[1]
		doc = GetMessages(messagesToCheck, doc, number, channelLink)
	}

	// extract v2ray based on message type and store configs at [configs] map
	// Always scan full message text (finds configs even when not inside code/pre blocks).
	doc.Find(".tgme_widget_message_text").Each(func(j int, s *goquery.Selection) {
		messageText, _ := s.Html()
		str := strings.ReplaceAll(messageText, "<br/>", "\n")
		doc, _ := goquery.NewDocumentFromReader(strings.NewReader(str))
		messageText = doc.Text()
		line := strings.TrimSpace(messageText)
		lines := strings.Split(line, "\n")
		for _, data := range lines {
			extractedConfigs := strings.Split(ExtractConfig(data, []string{}), "\n")
			for _, extractedConfig := range extractedConfigs {
				extractedConfig = strings.ReplaceAll(extractedConfig, " ", "")
				if extractedConfig == "" {
					continue
				}

				// check if it is vmess or not
				re := regexp.MustCompile(myregex["vmess"])
				matches := re.FindStringSubmatch(extractedConfig)

				if len(matches) > 0 {
					extractedConfig = EditVmessPs(extractedConfig, "mixed", false)
					if line != "" {
						configs["mixed"] += extractedConfig + "\n"
					}
				} else {
					configs["mixed"] += extractedConfig + "\n"
				}
			}
		}
	})
}

func ExtractConfig(Txt string, Tempconfigs []string) string {

	// filename can be "" or mixed
	for protoRegex, regexValue := range myregex {
		re := regexp.MustCompile(regexValue)
		matches := re.FindStringSubmatch(Txt)
		extractedConfig := ""
		if len(matches) > 0 {
			if protoRegex == "ss" {
				Prefix := strings.Split(matches[0], "ss://")[0]
				if Prefix == "" {
					extractedConfig = "\n" + matches[0]
				} else if Prefix != "vle" { //  (Prefix != "vme" && Prefix != "") always true!
					d := strings.Split(matches[0], "ss://")
					extractedConfig = "\n" + "ss://" + d[1]
				}
			} else if protoRegex == "vmess" {
				extractedConfig = "\n" + matches[0]
			} else {
				extractedConfig = "\n" + matches[0]
			}

			Tempconfigs = append(Tempconfigs, extractedConfig)
			Txt = strings.ReplaceAll(Txt, matches[0], "")
			ExtractConfig(Txt, Tempconfigs)
		}
	}
	d := strings.Join(Tempconfigs, "\n")
	return d
}

func EditVmessPs(config string, fileName string, AddConfigName bool) string {
	// Decode the base64 string
	if config == "" {
		return ""
	}
	slice := strings.Split(config, "vmess://")
	if len(slice) > 0 {
		decodedBytes, err := base64.StdEncoding.DecodeString(slice[1])
		if err == nil {
			// Unmarshal JSON into a map
			var data map[string]interface{}
			err = json.Unmarshal(decodedBytes, &data)
			if err == nil {
				if AddConfigName {
					ConfigFileIds[fileName] += 1
					data["ps"] = ConfigsNames + " - " + strconv.Itoa(int(ConfigFileIds[fileName])) + "\n"
				} else {
					data["ps"] = ""
				}

				// marshal JSON into a map
				jsonData, _ := json.Marshal(data)
				// Encode JSON to base64
				base64Encoded := base64.StdEncoding.EncodeToString(jsonData)

				return "vmess://" + base64Encoded
			}
		}
	}

	return ""
}

func loadMore(link string) *goquery.Document {
	fmt.Println(link)
	resp, err := HttpRequest(link)
	if err != nil {
		return nil
	}
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil
	}
	return doc
}

func HttpRequest(targetURL string) (*http.Response, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		if err2 := ensureTelegramProxy(targetURL); err2 == nil {
			req2, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				return nil, err
			}
			req2.Header.Set("User-Agent", "Mozilla/5.0")
			return client.Do(req2)
		}
		return nil, err
	}
	return resp, nil
}

func GetMessages(length int, doc *goquery.Document, number string, channel string) *goquery.Document {
	x := loadMore(channel + "?before=" + number)
	if x == nil {
		return doc
	}

	html2, _ := x.Html()
	reader2 := strings.NewReader(html2)
	doc2, _ := goquery.NewDocumentFromReader(reader2)

	doc.Find("body").AppendSelection(doc2.Find("body").Children())

	newDoc := goquery.NewDocumentFromNode(doc.Selection.Nodes[0])
	messages := newDoc.Find(".js-widget_message_wrap").Length()

	if messages > length {
		return newDoc
	} else {
		num, _ := strconv.Atoi(number)
		n := num - 21
		if n > 0 {
			ns := strconv.Itoa(n)
			GetMessages(length, newDoc, ns, channel)
		} else {
			return newDoc
		}
	}

	return newDoc
}
