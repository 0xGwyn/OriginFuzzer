
# Installation
```bash
go install github.com/0xGwyn/OriginFuzzer@latest
```
or
```bash
git clone https://github.com/0xGwyn/OriginFuzzer.git 
cd OriginFuzzer
go build -o $GOPATH/bin/originfuzzer main.go
```

# Usage 
```bash
originfuzzer -h
```
This will display help for the tool. Here are all the switches it supports.
```
Usage:
  originfuzzer [flags]

Flags:
  -l, -list string                    List of targets
  -v, -verbose                         Verbose output messages
  -sl, -subdomainlist string           List of subdomains to test on target for CORS Header check
  -s, -subdomain string                Single subdomain to test on target for CORS Header check
  -x, -header stringSlice              Custom headers to add to each request (\"key1:value1\",\"key2:value2\")
  -c, -cookie string                   Cookie values for each request
  -ua, -useragent string               Custom user-agent for requests
  -d, -delay duration                   Delay between each request
  -tm, -testmisconfig                  Test for CORS misconfigurations
  -ad, -attackerdomain string          Domain used for testing (default: "attacker.com")
  -p, -proxy string                    HTTP proxy to use
  -o, -output string                   Output filename
  -t, -timeout duration                 Request timeout duration (default: 10 seconds)
  -tn, -threads int                    Number of concurrent targets (default: 1)
```
