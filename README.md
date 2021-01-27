# fluent-plugin-sanitizer
The fluent-plugin-sanitzer is [Fluentd](https://fluentd.org/) filter plugin to sanitize sensitive information with custom rules. The fluent-plugin-sanitzer provides not only options to sanitize values with custom regular expression and keywords but also build-in options which allows users to easily sanitize IP addresses and hostnames in complex messages.

## Installation
When you are using OSS Fluentd :
```
fluent-gem install fluent-plugin-sanitizer
```
When you are using td-agent :
```
td-agent-gem install fluent-plugin-sanitizer
```

## Configuration
### Parameters
- hash_salt : specify hash salt used to sanitize original information (:string, default: nil)
- rule options
  - keys : Name of keys whose values are to be sanitized. You can specify multiple keys. When keys are nested, you can use {parent key}.{child key} like "kubernetes.master_url". (:array, default:[])
  - pattern_ipv4 : sanitize if values contain IPv4. (:bool, default: false)
  - pattern_fqdn : sanitize if values contain hostname in FQDN style. (:bool, default: false)
  - pattern_regex : sanitize if value mactchs custom regular expression (:regexp, default: /^$/)
  - pattern_keywords : sanitize if values match custom keywords. You can specify multiple keywords. (:array, default:[])

You can specify multiple options in a single rule like following sample configuration.
  
```
<filter **>
  @type sanitizer
  hash_salt mysalt
  <rule>
    keys source, kubernetes.master_url
    pattern_ipv4 true
  </rule>
  <rule>
    keys hostname, host
    pattern_fqdn true
  </rule>
  <rule>
    keys message, system.log
    pattern_regex /^Hello World!$/
    pattern_keywords password, passwd
  </rule>
</filter>
```

## Use cases

### Sanitize IP address and hostname
Sample rule #1
```
<rule>
  keys ip
  pattern_ipv4 true
</rule>
<rule>
  keys host
  pattern_fqdn true
</rule>
```
Sample input #1
```
{
  "ip":"192.168.10.10",
  "host":"test01.demo.com"
} 
```
Sample output #1
```
{
  "ip":"IPv4_94712b06963e277fe28469388323665d",
  "host":"FQDN_37de34e3d799de477c742d8d7bb35550"
}
```

### Sanitize IP addresses and hostnames in between URL and messages
You may sanitize IP addresses and hostnames in URL and messages. The "pattern_ipv4" and "pattern_fqdn" options can help you easily to sanitize information in such cases.

Sample rule #2
```
<rule>
  keys system.url, system.log
  pattern_ipv4 true
  pattern_fqdn true
</rule>
```
Sample input #2
```
{
  "tag":"test", 
  "system" : 
  {
    "url":"https://test02.demo.com:8000/event", 
    "log":"access from 192.168.10.100 was blocked"
  }
}
```
Sample output #3
```
{
  "tag":"test",
  "system":{
    "url":"https://FQDN_e9a59624f555d02f06209c9942dded19:8000/event",
    "log":"access from IPv4_f7374d61e6d21dc1105f70358a5f8e8f was blocked"
  }
}
```
### Sanitize keywords in between messages
When "pattern_keywords" option is selected, fluent-plugin-sanitizer splits messages and sanitizes blocks which match keywords.
Sample rule#3
```
<rule>
  keys message
  pattern_keywords user1, application1
</rule>
```
Sample input #3
```
{
  "message":"user1 failed to login application1"
}
```
Sample output #3
```
{
  "message":"Keyword_321865df6f0ce6bdf3ea16f74623534a failed to login Keyword_49006ff9b2ab584795e4cbb7636bd17c"
}
```
### Sanitize all messages
Sample rule #4
```
<rule>
  keys message
  pattern_regex /^.*$/
</rule>
```
Sample input#4
```
{
  "message":"user1 failed to login application1"
}
```
Sample output #4
```
{
  "message":"Regex_70e9b833f5f00a4b0ab9fcf74af81f26"
}
```
## Contribute
Contribution to fluent-plugin-sanitizer is always welcomed.


## Copyright
* Copyright(c) 2021- TK Kubota
* License
  * Apache License, Version 2.0
