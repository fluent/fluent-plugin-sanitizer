# fluent-plugin-sanitizer
Sanitizeris [Fluentd](https://fluentd.org/) filter plugin to mask sensitive information. With Sanitizer, you can mask based on key-value pairs on the fly in between Fluentd processes. Sanitizer provides options which enable you to mask values with custom rules. In custom rules, you can specify patterns such as IP addresses, hostnames in FQDN style, regular expressions and keywords. In terms of IP addresses and hostnames, Sanitizer delivers useful options which allows you to easily mask IP addresses and hostnames in complex messages.

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
- hash_salt (optional) : hash salt used when calculating hash value with original information. 
- hash_scheme (optional) : Hash scheme to use for generating hash value. Supported schemes are `md5`,`sha1`,`sha256`,`sha384` and `sha512`. (default: `md5`)
- rule options : 
  - keys (mandatory) :  Name of keys whose values will be masked. You can specify multiple keys. When keys are nested, you can use {parent key}.{child key} like "kubernetes.master_url". 
  - pattern_ipv4 (optional)  : Mask IP addresses in IPv4 format. You can use “true” or “false”. (defalt: false)
  - pattern_fqdn (optional)  : Mask hostname in FQDN style. You can use “true” or “false”. (defalt: false)
  - pattern_regex (optional)  : Mask value mactches custom regular expression.
    - regex_capture_group (optional) : If you define capture group in regular expression, you can specify the name of capture group to be masked.
    - pattern_regex_prefix (optional) : Define prefix used for masking vales. (default: Regex)
  - pattern_keywords (optional)  : Mask values match custom keywords. You can specify multiple keywords. 
    - pattern_keywords_prefix (optional) : Define prefix used for masking vales. (default: Keyword)

You can specify multiple rules in a single configuration. It is also possible to define multiple pattern options in a single rule like the following sample.
  
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
### Mask IP addresses and Hostnames
Masking IP addresses and hostnames is one of the typical use cases of security operations. You just need to specify the name of keys that potentially  have IP addresses and hostnames in value. Here is a configuration sample as well as input and output samples. 

**Configuration sample**
```
<filter **>
  @type sanitizer
  hash_salt mysalt
  hash_scheme md5
  <rule>
    keys ip
    pattern_ipv4 true
  </rule>
  <rule>
    keys host
    pattern_fqdn true
  </rule>
  <rule>
    keys system.url, system.log
    pattern_ipv4 true
    pattern_fqdn true
  </rule>
</filter>
```
**Input sample**
```
 {
     "ip" : "192.168.10.10",
     "host" : "test01.demo.com",
      "system" : {
         "url" : "https://test02.demo.com:8000/event",
         "log" : "access from 192.168.10.100 was blocked"
     }
  }
```
**Output sample**
```
 {
     "ip" : "IPv4_94712b06963e277fe28469388323665d",
     "host" : "FQDN_37de34e3d799de477c742d8d7bb35550",
     "system" : {
         "url" : "https://FQDN_e9a59624f555d02f06209c9942dded19:8000/event"
         "log" : "access from IPv4_f7374d61e6d21dc1105f70358a5f8e8f was blocked"
     }
 }
```
### Mask words match custom keyword and regular expression
In case log messages including sensitive information such as SSN and phone number, Sanitizer could also help you. If you know the exact keyword that needs to be masked, you can use the keyword option. You can also use the regex option if you like to mask information which matches custom a regular expression.

**Configuration sample**
```
<filter **>
  @type sanitizer
  hash_salt mysalt
  <rule>
    keys user.ssn
    pattern_regex /^(?!(000|666|9))\d{3}-(?!00)\d{2}-(?!0000)\d{4}$/
    pattern_regex_prefix SSN
  </rule>
  <rule>
    keys user.phone
    pattern_regex /^\d{3}-?\d{3}-?\d{4}$/
    pattern_regex_prefix Phone
  </rule>
</filter>
```
**Input sample**
```
 {
     "user" : {
         "ssn" : "123-45-6789"
         "phone" : "123-456-7890"
     }
 }
```
**Output sample**
```
 {
     "user" : {
         "ssn" : "SSN_f6b6430343a9a749e12db8a112ca74e9"
         "phone" : "Phone_0a25187902a0cf755627397eb085d736"
     }
 }
```
From v0.1.2, "regex_capture_group" option is available. With "regex_capture_group" option, it is possible to mask specific part of original messages. 

**Configuration sample**
```
<rule>
  keys user.email
  pattern_regex /(?<user>\w+)\@\w+.\w+/
  regex_capture_group "user"
  pattern_regex_prefix "USER"
</rule>
```
**Input sample**
```
 {
     "user" : {
         "email" : "user1@demo.com"
     }
 }
```
**Output sample**
```
 {
     "user" : {
         "email" : "USER_321865df6f0ce6bdf3ea16f74623534a@demo.com"
     }
 }
```

### Tips : Debug how sanitizer works
When you design custom rules in a configuration file, you might need information about how Sanitizer masks original values into hash values for debugging purposes. You can check that information if you run td-agent/Fluentd with debug option enabled. The debug information is shown in the log file of td-agent/Fluentd like the following log message sample.

**Log message sample**
```
YYYY-MM-DD Time fluent.debug: {"message":"[pattern_regex] sanitize '123-45-6789' to 'SSN_f6b6430343a9a749e12db8a112ca74e9'"}
YYYY-MM-DD Time fluent.debug: {"message":"[pattern_regex] sanitize '123-456-7890' to 'Phone_0a25187902a0cf755627397eb085d736'"}
```
## Contribute
Contribution to fluent-plugin-sanitizer is always welcomed.


## Copyright
* Copyright(c) 2021- TK Kubota
* License
  * Apache License, Version 2.0
