#
# Copyright 2021- TK Kubota
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "fluent/plugin/filter"
require "digest"

module Fluent
  module Plugin
    class SanitizerFilter < Fluent::Plugin::Filter
      Fluent::Plugin.register_filter("sanitizer", self)

      helpers :event_emitter, :record_accessor

      desc "Hash salt to be used to generate hash values with MD5(optional)"
      config_param :hash_salt, :string, default: ""
      
      config_section :rule, param_name: :rules, multi: true do 
        desc "Name of keys whose valuse are to be sanitized"
        config_param :keys, :array, default: []
        desc "Sanitize if values contain IPv4 (optional)"
        config_param :pattern_ipv4, :bool, default: false
        desc "Sanitize if values contain Hostname in FQDN style (ptional)"
        config_param :pattern_fqdn, :bool, default: false
        desc "Sanitize if values mactch custom regular expression (optional)"
        config_param :pattern_regex, :regexp, default: /^$/
        desc "Prefix for pattern_regex (optional)"
        config_param :regex_capture_group, :string, default:""
        desc "Target capture group name to be masked (optional)"
        config_param :pattern_regex_prefix, :string, default: "Regex"
        desc "Sanitize if values mactch custom keywords (optional)"
        config_param :pattern_keywords, :array, default: []
        desc "Prefix for pattern_keywords (optional)"
        config_param :pattern_keywords_prefix, :string, default: "Keywords"
      end

      def configure(conf)
        super
      
        @salt = conf['hash_salt']
 
        @sanitizerules = []
        @rules.each do |rule|
          if rule.keys.empty?
            raise Fluent::ConfigError, "You need to specify at least one key in rule statement."
          else
            #keys = record_accessor_create(rule.keys)
            keys = rule.keys
          end
          
          #record_accessor_create(rule.keys)
          
          if rule.pattern_ipv4 || !rule.pattern_ipv4
            pattern_ipv4 = rule.pattern_ipv4
          else
            raise Fluent::ConfigError, "true or false is available for pattern_ipv4 option."
          end
 
          if rule.pattern_fqdn || !rule.pattern_fqdn
            pattern_fqdn = rule.pattern_fqdn
          else
            raise Fluent::ConfigError, "true or false is available for pattern_fqdn option."
          end
          
          if rule.pattern_regex.class == Regexp
            pattern_regex = rule.pattern_regex
            regex_capture_group = rule.regex_capture_group
          else
            raise Fluent::ConfigError, "Your need to specify Regexp for pattern_fqdn option."
          end      
    
          pattern_keywords = rule.pattern_keywords

          case [pattern_ipv4, pattern_fqdn, pattern_regex, pattern_keywords.empty?]
          when [false, false, /^$/, true]
            raise Fluent::ConfigError, "You need to specify at least one pattern option in the rule statement." 
          end
      
          regex_prefix = rule.pattern_regex_prefix
          keywords_prefix = rule.pattern_keywords_prefix

          @sanitizerules.push([keys, pattern_ipv4, pattern_fqdn, pattern_regex, regex_capture_group, pattern_keywords, regex_prefix, keywords_prefix])
        end
      end

      def filter(tag, time, record)
        @sanitizerules.each do |keys, pattern_ipv4, pattern_fqdn, pattern_regex, regex_capture_group, pattern_keywords, regex_prefix, keywords_prefix|  
          keys.each do |key|
            accessor = record_accessor_create("$."+key.to_s)
            if pattern_ipv4
              accessor.set(record, sanitize_ipv4_val(accessor.call(record).to_s))
            end
            if pattern_fqdn
              accessor.set(record, sanitize_fqdn_val(accessor.call(record).to_s))
            end
            if pattern_regex
              if regex_capture_group.empty?
                accessor.set(record, sanitize_regex_val(accessor.call(record).to_s, regex_prefix, pattern_regex))
              else
                accessor.set(record, sanitize_regex_val_capture(accessor.call(record).to_s, regex_prefix, pattern_regex, regex_capture_group))
              end
            end
            if !pattern_keywords.empty?
              accessor.set(record, sanitize_keywords_val(accessor.call(record).to_s, pattern_keywords, keywords_prefix))
            end
          end
        end
        record
      end

      def include_ipv4?(str)
        str.match?(/^.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*$/)
      end

      def is_ipv4?(str)
        str.match?(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)
      end

      def is_ipv4_port?(str)
        str.match?(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:[0-9]{1,5}$/)
      end

      def include_fqdn?(str)
        str.match?(/^.*\b(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.){2,}([A-Za-z]|[A-Za-z][A-Za-z\-]*[A-Za-z]){2,}.*$/)
      end

      def is_fqdn?(str)
        str.match?(/^\b(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.){2,}([A-Za-z]|[A-Za-z][A-Za-z\-]*[A-Za-z]){2,}$/)
      end

      def is_fqdn_port?(str)
        str.match?(/^\b(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.){2,}([A-Za-z]|[A-Za-z][A-Za-z\-]*[A-Za-z]){2,}:[0-9]{1,5}$/)
      end

      def is_url?(str)
        str.match?(/^[a-zA-Z0-9]{2,}:\/\/.*$/)
      end

      def subtract_quotations(str)
        str.gsub(/\\\"|\'|\"|\\\'/,'')
      end

      def sanitize_ipv4(str)
        return "IPv4_"+Digest::MD5.hexdigest(@salt + str)
      end

      def sanitize_fqdn(str)
        return "FQDN_"+Digest::MD5.hexdigest(@salt + str)
      end

      def sanitize_regex(str, prefix, regex)
        if str.to_s.match?(regex)
          return prefix + "_" + Digest::MD5.hexdigest(@salt + str)
        else
          $log.debug "[pattern_regex] #{str} does not match given regex #{regex}. skip this rule."
          return str
        end
      end

      def sanitize_regex_capture(str, prefix, regex, capture_group)
        if str.match?(regex)
          if str.match(regex).names.include?(capture_group)
            cg = str.match(regex)[capture_group]
            mask = prefix + "_" + Digest::MD5.hexdigest(@salt + cg)
            return str.split(cg)[0] + mask + str.split(cg)[1]
          else
             $log.debug "[pattern_regex] regex pattern matched but capture group '#{capture_group}' does not exist. Skip this rule."
             return str
          end
        else
          $log.debug "[pattern_regex] #{str} does not match given regex #{regex}. Skip this rule."
          return str
        end
      end
      
      def sanitize_keyword(str, prefix)
        return prefix + "_" + Digest::MD5.hexdigest(@salt + str)
      end

      def sanitize_ipv4_port(str)
        ip_port = []
        str.split(":").each do |s|
          s =  sanitize_ipv4(s) if is_ipv4?(s)
          ip_port.push(s)
        end
        return ip_port.join(":")
      end

      def sanitize_fqdn_port(str)
        fqdn_port = []
        str.split(":").each do |s|
          s = sanitize_fqdn(s) if is_fqdn?(s)
          fqdn_port.push(s)
        end
        return fqdn_port.join(":")
      end

      def sanitize_ipv4_url(str)
        ip_url = []
        str.split("://").each do |s|
          if s.include?("/")
            url_slash = []
            s.split("/").each do |ss|
              ss = sanitize_ipv4(ss) if is_ipv4?(ss)
              ss = sanitize_ipv4_port(ss) if is_ipv4_port?(ss)
              url_slash.push(ss)
            end
            s = url_slash.join("/")
          else
            s = sanitize_ipv4_port(s) if is_ipv4_port?(s)
            s = sanitize_ipv4_port(s) if is_ipv4_port?(s)
          end
          ip_url.push(s)
        end
        return ip_url.join("://")
      end

      def sanitize_fqdn_url(str)
        fqdn_url = []
        str.split("://").each do |s|
          if s.include?("/")
            url_slash = []
            s.split("/").each do |ss|
              ss = sanitize_fqdn(ss) if is_fqdn?(ss)
              ss = sanitize_fqdn_port(ss) if is_fqdn_port?(ss)
              url_slash.push(ss)
            end
            s = url_slash.join("/")
          else
            s = sanitize_fqdn(s) if is_fqdn?(s)
            s = sanitize_fqdn_port(s) if is_fqdn_port?(s)
          end
          fqdn_url.push(s)
        end
        return fqdn_url.join("://")
      end

      def sanitize_ipv4_val(v)
        line = []
        if v.include?(",")
          v.split(",").each do |s|
            s = subtract_quotations(s)
            if include_ipv4?(s)
              if is_url?(s)
                s = sanitize_ipv4_url(s)
              else
                s = sanitize_ipv4(s) if is_ipv4?(s)
                s = sanitize_ipv4_port(s) if is_ipv4_port?(s)
              end
            end
            line.push(s)
          end
          return line.join(",")
        else
          v.split().each do |s|
            s = subtract_quotations(s)
            if include_ipv4?(s)
              if is_url?(s)
                s = sanitize_ipv4_url(s)
              else
                s = sanitize_ipv4(s) if is_ipv4?(s)
                s = sanitize_ipv4_port(s) if is_ipv4_port?(s)
              end
            end
            line.push(s)
          end
          $log.debug "[pattern_ipv4] sanitize '#{v}' to '#{line.join(" ")}'" if v != line.join(" ")
          return line.join(" ")
        end
      end

      def sanitize_fqdn_val(v)
        line = []
        if v.include?(",")
          v.split(",").each do |s|
            s = subtract_quotations(s)
            if include_fqdn?(s)
              if is_url?(s)
                s = sanitize_fqdn_url(s)
              else
                s = sanitize_fqdn(s) if is_fqdn?(s)
                s = sanitize_fqdn_port(s) if is_fqdn_port?(s)
              end
            end
            line.push(s)
          end
          return line.join(",")
        else
          v.split().each do |s|
            s = subtract_quotations(s)
            if include_fqdn?(s)
              if is_url?(s)
                s = sanitize_fqdn_url(s)
              else
                s = sanitize_fqdn(s) if is_fqdn?(s)
                s = sanitize_fqdn_port(s) if is_fqdn_port?(s)
              end
            end
            line.push(s)
          end
          $log.debug "[pattern_fqdn] sanitize '#{v}' to '#{line.join(" ")}'" if v != line.join(" ")
          return line.join(" ")
        end
      end

      def sanitize_regex_val(v, prefix, regex)
        s = sanitize_regex(v, prefix, regex)  
        $log.debug "[pattern_regex] sanitize '#{v}' to '#{s}'" if v != s
        return s
      end

      def sanitize_regex_val_capture(v, prefix, regex, capture_group)
        s = sanitize_regex_capture(v, prefix, regex, capture_group)
        $log.debug "[pattern_regex] sanitize '#{v}' to '#{s}'" if v != s
        return s
      end

      def sanitize_keywords_val(v, keywords, prefix)
        line = []
        v.split().each do |vv|
          if keywords.include?(vv)
            line.push(sanitize_keyword(vv, prefix))
          else
            line.push(vv)
           end
        end
        $log.debug "[pattern_keywords] sanitize '#{v}' to '#{line.join(" ")}'" if v != line.join(" ")
        return line.join(" ")
      end

    end
  end
end
