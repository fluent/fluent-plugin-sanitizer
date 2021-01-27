#
# Copyright 2021- TODO: Write your name
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
require "openssl"

module Fluent
  module Plugin
    class SanitizerFilter < Fluent::Plugin::Filter
      Fluent::Plugin.register_filter("sanitizer", self)

      helpers :event_emitter, :record_accessor

      desc "Hash salt to be used to generate hash values with MD5(optional)"
      config_param :hash_salt, :string, default: nil
      
      config_section :rule, param_name: :rules, multi: true do 
        desc "Name of keys whose valuse are to be sanitized"
        config_param :keys, :array, default: []
        desc "Sanitize if values contain IPv4 (optional)"
        config_param :pattern_ipv4, :bool, default: false
        desc "Sanitize if values contain Hostname in FQDN style (ptional)"
        config_param :pattern_fqdn, :bool, default: false
        desc "Sanitize if values mactch custom regular expression (optional)"
        config_param :pattern_regex, :regexp, default: /^$/
        desc "Sanitize if values mactch custom keywords (optional)"
        config_param :pattern_keywords, :array, default: []
      end

      #def initialize
      #  super
      #  @salt = nil
      #end

      def configure(conf)
        super
      
        @salt = ""
        @salt = conf['hash_salt'] if conf['hash_salt'] != nil
 
        @sanitizerules = []
        @rules.each do |rule|
          if rule.keys.empty?
            raise Fluent::ConfigError, "You need to specify at least one key in rule statement."
          else
            keys = rule.keys
          end
          
          if rule.pattern_ipv4 == true || rule.pattern_ipv4 == false
            pattern_ipv4 = rule.pattern_ipv4
          else
            raise Fluent::ConfigError, "true or false is available for pattern_ipv4 option."
          end
 
          if rule.pattern_fqdn == true || rule.pattern_fqdn == false
            pattern_fqdn = rule.pattern_fqdn
          else
            raise Fluent::ConfigError, "true or false is available for pattern_fqdn option."
          end
        
          pattern_regex = rule.pattern_regex
          pattern_keywords = rule.pattern_keywords

          case [pattern_ipv4, pattern_fqdn, pattern_regex, pattern_keywords.empty?]
          when [false, false, /^$/, true]
            raise Fluent::ConfigError, "You need to specify at least one pattern option in the rule statement." 
          end
          @sanitizerules.push([keys, pattern_ipv4, pattern_fqdn, pattern_regex, pattern_keywords])
	      end
      end

      def filter(tag, time, record)
	      @sanitizerules.each do |keys, pattern_ipv4, pattern_fqdn, pattern_regex, pattern_keywords|
          
          keys.each do |key|
            if key.include?(".")
              nkey = key.split(".")
              if nkey.length ==2
                if record[nkey[0]].key?(nkey[1])
                  v = record[nkey[0]][nkey[1]]
                  record[nkey[0]][nkey[1]] = sanitize_ipv4_val(@salt, record[nkey[0]][nkey[1]]) if pattern_ipv4 == true
                  record[nkey[0]][nkey[1]] = sanitize_fqdn_val(@salt, record[nkey[0]][nkey[1]]) if pattern_fqdn == true
                  record[nkey[0]][nkey[1]] = sanitize_regex(@salt, record[nkey[0]][nkey[1]]) if is_regex?(pattern_regex) && !!(pattern_regex =~ record[nkey[0]][nkey[1]])
                  record[nkey[0]][nkey[1]] = sanitize_keyword(@salt, pattern_keywords, record[nkey[0]][nkey[1]]) if pattern_keywords.empty? == false
                else
                  $log.error "no such nested key found : key name = #{key}" 
                end
              elsif nkey.length ==3
                if record[nkey[0]][nkey[1]].key?(nkey[2])
                  v = record[nkey[0]][nkey[1]][nkey[2]]
                  record[nkey[0]][nkey[1]][nkey[2]] = sanitize_ipv4_val(@salt, record[nkey[0]][nkey[1]][nkey[2]]) if pattern_ipv4 == true
                  record[nkey[0]][nkey[1]][nkey[2]] = sanitize_fqdn_val(@salt, record[nkey[0]][nkey[1]][nkey[2]]) if pattern_fqdn == true
                  record[nkey[0]][nkey[1]][nkey[2]] = sanitize_regex(@salt, record[nkey[0]][nkey[1]][nkey[2]]) if is_regex?(pattern_regex) && !!(pattern_regex =~ record[nkey[0]][nkey[1]][nkey[2]])
                  record[nkey[0]][nkey[1]][nkey[2]] = sanitize_keyword(@salt, pattern_keywords, record[nkey[0]][nkey[1]][nkey[2]]) if pattern_keywords.empty? == false
                else
                  $log.error "no such nested key found : key name = #{key}"
                end
              end
            else
	            if record.key?(key)
                v = record[key]
                record[key] = sanitize_ipv4_val(@salt, record[key]) if pattern_ipv4 == true
                record[key] = sanitize_fqdn_val(@salt, record[key]) if pattern_fqdn == true
                record[key] = sanitize_regex(@salt, v) if is_regex?(record[key]) && !!(pattern_regex =~ record[key])
                record[key] = sanitize_keyword_val(@salt, pattern_keywords, v) if pattern_keywords.empty? == false
              else
                $log.error "no such key found : key name = #{key}"
	            end
            end
	        end
	        puts record
        end
      end

      def include_ipv4?(str)
        !!(str =~ /^.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*$/)
      end

      def is_ipv4?(str)
        !!(str =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)
      end

      def is_ipv4_port?(str)
        !!(str =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:[0-9]{1,5}$/)
      end

      def include_fqdn?(str)
        !!(str =~ /^.*\b(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.){2,}([A-Za-z]|[A-Za-z][A-Za-z\-]*[A-Za-z]){2,}.*$/)
      end

      def is_fqdn?(str)
        !!(str =~ /^\b(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.){2,}([A-Za-z]|[A-Za-z][A-Za-z\-]*[A-Za-z]){2,}$/)
      end

      def is_fqdn_port?(str)
        !!(str =~ /^\b(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.){2,}([A-Za-z]|[A-Za-z][A-Za-z\-]*[A-Za-z]){2,}:[0-9]{1,5}$/)
      end

      def is_url?(str)
        !!(str =~ /^[a-zA-Z0-9]{2,}:\/\/.*$/)
      end

      def is_regex?(regex)
        return regex.class == Regexp
      end

      def subtract_quotations(str)
        return str.gsub(/\\\"|\'|\"|\\\'/,'')
      end

      def sanitize_ipv4(salt, str)
        return str, "IPv4_"+Digest::MD5.hexdigest(salt + str)
      end

      def sanitize_fqdn(salt, str)
        return str, "FQDN_"+Digest::MD5.hexdigest(salt + str)
      end

      def sanitize_regex(salt, str)
        return "Regex_"+Digest::MD5.hexdigest(salt + str)
      end
      
      def sanitize_keyword(salt, str)
        return "Keyword_"+Digest::MD5.hexdigest(salt + str)
      end

      def sanitize_ipv4_port(salt, str)
        ip_port = []
        str.split(":").each do |s|
          b, s =  sanitize_ipv4(salt, s) if is_ipv4?(s)
          ip_port.push(s)
        end
        return str, ip_port.join(":")
      end

      def sanitize_fqdn_port(salt, str)
        fqdn_port = []
        str.split(":").each do |s|
          b, s =  sanitize_fqdn(salt, s) if is_fqdn?(s)
          fqdn_port.push(s)
        end
        return str, fqdn_port.join(":")
      end

      def sanitize_ipv4_url(salt, str)
        ip_url = []
        str.split("://").each do |s|
          if s.include?("/")
            url_slash = []
            s.split("/").each do |ss|
              b, ss = sanitize_ipv4(salt, ss) if is_ipv4?(ss)
              b, ss = sanitize_ipv4_port(salt, ss) if is_ipv4_port?(ss)
              url_slash.push(ss)
            end
            s = url_slash.join("/")
          else
            b, s = sanitize_ipv4(salt, s) if is_ipv4?(s)
            b, s = sanitize_ipv4_port(salt, s) if is_ipv4_port?(s)
          end
          ip_url.push(s)
        end
        return str, ip_url.join("://")
      end

      def sanitize_fqdn_url(salt, str)
        fqdn_url = []
        str.split("://").each do |s|
          if s.include?("/")
            url_slash = []
            s.split("/").each do |ss|
              b, ss = sanitize_fqdn(salt, ss) if is_fqdn?(ss)
              b, ss = sanitize_fqdn_port(salt, ss) if is_fqdn_port?(ss)
              url_slash.push(ss)
            end
            s = url_slash.join("/")
          else
            b, s = sanitize_fqdn(salt, s) if is_fqdn?(s)
            b, s = sanitize_fqdn_port(salt, s) if is_fqdn_port?(s)
          end
          fqdn_url.push(s)
        end
        return str, fqdn_url.join("://")
      end

      def sanitize_ipv4_val(salt, v)
        line = []
        if v.include?(",")
          v.split(",").each do |s|
            s = subtract_quotations(s)
            if include_ipv4?(s)
              if is_url?(s)
                b, s = sanitize_ipv4_url(salt, s)
              else
                b, s = sanitize_ipv4(salt, s) if is_ipv4?(s)
                b, s = sanitize_ipv4_port(salt, s) if is_ipv4_port?(s)
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
                b, s = sanitize_ipv4_url(salt, s)
              else
                b, s = sanitize_ipv4(salt, s) if is_ipv4?(s)
                b, s = sanitize_ipv4_port(salt, s) if is_ipv4_port?(s)
              end
            end
            line.push(s)
          end
          return line.join(" ")
        end
      end

      def sanitize_fqdn_val(salt, v)
        line = []
        if v.include?(",")
          v.split(",").each do |s|
            s = subtract_quotations(s)
            if include_fqdn?(s)
              if is_url?(s)
                b, s = sanitize_fqdn_url(salt, s)
              else
                b, s = sanitize_fqdn(salt, s) if is_fqdn?(s)
                b, s = sanitize_fqdn_port(salt, s) if is_fqdn_port?(s)
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
                b, s = sanitize_fqdn_url(salt, s)
              else
                b, s = sanitize_fqdn(salt, s) if is_fqdn?(s)
                b, s = sanitize_fqdn_port(salt, s) if is_fqdn_port?(s)
              end
            end
            line.push(s)
          end
          return line.join(" ")
        end
      end

      def sanitize_keyword_val(salt, keywords, v)
        line = []
        v.split().each do |vv|
          if keywords.include?(vv)
            line.push(sanitize_keyword(salt, vv))
          else
            line.push(vv)
           end
        end
        return line.join(" ")
      end

    end
  end
end
