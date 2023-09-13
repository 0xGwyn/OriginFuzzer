package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	fileUtil "github.com/projectdiscovery/utils/file"
)

type Options struct {
	List           string
	Verbose        bool
	SubdomainList  string
	Subdomain      string
	Header         goflags.StringSlice
	Cookie         string
	UserAgent      string
	Delay          time.Duration
	Proxy          string
	TestMisconfig  bool
	AttackerDomain string
	Output         string
	Timeout        time.Duration
	Threads        int
}

func parseArgs() *Options {
	options := &Options{}

	flags := goflags.NewFlagSet()
	flags.SetDescription("CORS misconfiguration fuzzer for regex bypass")

	flags.StringVarP(&options.List, "list", "l", "", "List of targets")
	flags.BoolVarP(&options.Verbose, "verbose", "v", false, "Verbose output messages")
	flags.StringVarP(&options.SubdomainList, "subdomainlist", "sl", "", "List of subdomains in order to test on target for CORS Header check")
	flags.StringVarP(&options.Subdomain, "subdomain", "s", "", "Single subdomain in order to test on target for CORS Header check")
	flags.StringSliceVarP(&options.Header, "header", "x", goflags.StringSlice{}, "Any custom headers that you want to add to each request (\"key1:value1\",\"key2:value2\")", goflags.CommaSeparatedStringSliceOptions)
	flags.StringVarP(&options.Cookie, "cookie", "c", "", "Cookie values for each request")
	flags.StringVarP(&options.UserAgent, "useragent", "ua", "", "Custom user-agent for requests")
	flags.DurationVarP(&options.Delay, "delay", "d", 0, "Delay between each request")
	flags.BoolVarP(&options.TestMisconfig, "testmisconfig", "tm", true, "Test for CORS misconfigs")
	flags.StringVarP(&options.AttackerDomain, "attackerdomain", "ad", "attacker.com", "Delay between each request")
	flags.StringVarP(&options.Proxy, "proxy", "p", "", "http proxy to use")
	flags.StringVarP(&options.Output, "output", "o", "", "Output filename")
	flags.DurationVarP(&options.Timeout, "timeout", "t", time.Second*10, "Delay between each request")
	flags.IntVarP(&options.Threads, "threads", "tn", 1, "Number of concurrent targets")

	if err := flags.Parse(); err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	return options
}

var options *Options

func main() {
	options = parseArgs()

	targetList := getURLs()
	subdomainList := getSubdomains()

	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	if strings.Contains(options.AttackerDomain, "http") || strings.Contains(options.AttackerDomain, "https") {
		gologger.Fatal().Msg("Please enter Attacker-Domain without scheme")
	}

	requestHeaders := map[string]string{}
	if options.UserAgent != "" {
		requestHeaders["User-Agent"] = options.UserAgent
	} else {
		requestHeaders["User-Agent"] = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"
	}

	if options.Cookie != "" {
		requestHeaders["Cookie"] = options.Cookie
	}

	if len(options.Header) != 0 {
		for _, header := range options.Header {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) != 2 {
				gologger.Fatal().Msg("Please enter custom header in valid format!\nFormat --> -x \"key1:value1\" \"key2:value2\"")
			}
			key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			requestHeaders[key] = value
		}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var numOfGoroutines int
	if options.Threads > len(targetList) {
		numOfGoroutines = len(targetList)
	} else {
		numOfGoroutines = options.Threads
	}
	wg.Add(numOfGoroutines)

	urlsPerThread := len(targetList) / options.Threads
	remainingURLs := len(targetList) % options.Threads

	output := []map[string]interface{}{}
	for thread := 0; thread < numOfGoroutines; thread++ {
		start := thread * urlsPerThread
		end := start + urlsPerThread

		if thread == numOfGoroutines-1 {
			end += remainingURLs
		}

		go func(urls []string) {
			defer wg.Done()

			for _, url := range urls {
				scheme := "https"
				if strings.HasPrefix(url, "http://") {
					scheme = "http"
				}
				rawTarget := cleanTarget(url)

				if result := runAttack(url, scheme, rawTarget, options.AttackerDomain, false, requestHeaders); result != nil {
					mu.Lock()
					output = append(output, result)
					mu.Unlock()
					time.Sleep(options.Delay)
				}
				if len(subdomainList) >= 1 {
					if result := runAttack(url, scheme, "", options.AttackerDomain, true, requestHeaders); result != nil {
						mu.Lock()
						output = append(output, result)
						mu.Unlock()
						time.Sleep(options.Delay)
					}
				}
			}
		}(targetList[start:end])

	}
	wg.Wait()

	// save output as json
	if options.Output != "" {
		if len(output) != 0 {
			saveOutput(output, options.Output)
		}
	}

}

func runAttack(target, scheme, domain, attackerDomain string, subdomainCheck bool, headers map[string]string) map[string]interface{} {
	origins := []string{
		fmt.Sprintf("%s://NonExistenceSubdomainToTest.%s", scheme, domain),
		fmt.Sprintf("%s://%s.%s", scheme, domain, attackerDomain),
		fmt.Sprintf("%s://%s_%s", scheme, domain, attackerDomain),
		fmt.Sprintf("%s://%s", scheme, attackerDomain),
		fmt.Sprintf("%s://%s%s", scheme, domain, attackerDomain),
		fmt.Sprintf("%s://%s%s", scheme, attackerDomain, domain),
		"null",
		"sample.computer",
		fmt.Sprintf("%s://%s%%09%s", scheme, domain, attackerDomain),
		fmt.Sprintf("%s://%s%%60.%s", scheme, domain, attackerDomain),
		fmt.Sprintf("%s://foo@%s:80@%s", scheme, attackerDomain, domain),
		fmt.Sprintf("%s://foo@%s%%20%s", scheme, attackerDomain, domain),
		fmt.Sprintf("%s://%s@%s", scheme, domain, attackerDomain),
		fmt.Sprintf("%s://%s#%s", scheme, domain, attackerDomain),
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if options.Proxy != "" {
		proxyURL, err := url.Parse(options.Proxy)
		if err != nil {
			gologger.Warning().Msg("Warning while using proxy: " + err.Error())
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   options.Timeout,
	}

	if !subdomainCheck && options.TestMisconfig {
		gologger.Print().Msgf("Testing origin misconfiguration for %s [%s]", target, currentTime())

		for _, origin := range origins {
			headers["Origin"] = origin
			attackRequest, err := http.NewRequest("GET", target, nil)
			if err != nil {
				gologger.Warning().Msgf("Failed to create request with origin==%s.\n\t%s", origin, err.Error())
				continue
			}
			for key, value := range headers {
				attackRequest.Header.Set(key, value)
			}

			resp, err := client.Do(attackRequest)
			if err != nil {
				gologger.Print().Msgf("Failed to connect to target.\n\t%s", err)
				continue
			}
			defer resp.Body.Close()

			responseHeaders := resp.Header

			if _, ok := responseHeaders["Access-Control-Allow-Credentials"]; ok {
				if _, ok := responseHeaders["Access-Control-Allow-Origin"]; ok {
					tmpOutput := map[string]interface{}{
						"origin":                           origin,
						"target":                           target,
						"Access-Control-Allow-Credentials": responseHeaders["Access-Control-Allow-Credentials"][0],
						"type":                             "potential misconfig",
					}
					jsonData, err := json.MarshalIndent(tmpOutput, "", "  ")
					if err != nil {
						gologger.Fatal().Msg("Error while parsing to json to print: " + err.Error())
					}
					fmt.Println(string(jsonData) + "\n")

					return tmpOutput
				}
			}

		}
	}

	if subdomainCheck {
		gologger.Print().Msgf("Testing for whitelisted origins (subdomains) [%s]", currentTime())

		if options.SubdomainList == "" {
			return nil
		}

		file, err := os.Open(options.SubdomainList)
		if err != nil {
			gologger.Fatal().Msg("Error opening file: " + err.Error())
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			subdomain := scanner.Text()
			if !strings.HasPrefix(subdomain, "http://") && !strings.HasPrefix(subdomain, "https://") {
				subdomain = fmt.Sprintf("%s://%s", scheme, subdomain)
			}

			headers["Origin"] = subdomain

			attackRequest, err := http.NewRequest("GET", target, nil)
			if err != nil {
				gologger.Warning().Msgf("Failed to create request with subdomain==%s.\n\t%s", subdomain, err.Error())
				continue
			}
			for key, value := range headers {
				attackRequest.Header.Set(key, value)
			}

			resp, err := client.Do(attackRequest)
			if err != nil {
				gologger.Warning().Msgf("Failed to connect to target.\n\t%s", err)
				continue
			}
			defer resp.Body.Close()

			responseHeaders := resp.Header

			if _, ok := responseHeaders["Access-Control-Allow-Credentials"]; ok {
				if _, ok := responseHeaders["Access-Control-Allow-Origin"]; ok {
					tmpOutput := map[string]interface{}{
						"origin":                           subdomain,
						"target":                           target,
						"Access-Control-Allow-Credentials": responseHeaders["Access-Control-Allow-Credentials"][0],
						"type":                             "potential whitelisted subdomain",
					}
					jsonData, err := json.MarshalIndent(tmpOutput, "", "  ")
					if err != nil {
						gologger.Fatal().Msg("Error while parsing to json to print: " + err.Error())
					}
					fmt.Println(string(jsonData) + "\n")

					return tmpOutput
				}
			}
		}
	}

	return nil
}

func cleanTarget(data string) string {
	u, err := url.Parse(data)
	if err != nil {
		gologger.Warning().Msg("Error occurred while cleaning/parsing target: " + data)
		return ""
	}

	return u.Host
}

func currentTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

func saveOutput(data []map[string]interface{}, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")

	err = encoder.Encode(data)
	if err != nil {
		fmt.Println("Error encoding JSON:", err)
	}
}

func getURLs() []string {
	urls := []string{}

	// read input from a file otherwise read from stdin
	if options.List != "" {
		ch, err := fileUtil.ReadFile(options.List)
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		for url := range ch {
			urls = append(urls, url)
		}
	} else if fileUtil.HasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			urls = append(urls, strings.TrimSpace(scanner.Text()))
		}
		if err := scanner.Err(); err != nil {
			gologger.Fatal().Msg(err.Error())
		}
	}

	return urls
}

func getSubdomains() []string {
	subdomains := []string{}

	if options.SubdomainList != "" {
		ch, err := fileUtil.ReadFile(options.SubdomainList)
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		for subdomain := range ch {
			subdomains = append(subdomains, subdomain)
		}
	} else if options.Subdomain != "" {
		subdomains = append(subdomains, options.Subdomain)
	}

	return subdomains
}
