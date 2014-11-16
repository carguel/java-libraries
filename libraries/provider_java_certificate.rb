#
# Author:: Mevan Samaratunga (<mevansam@gmail.com>)
# Author:: Michael Goetz (<mpgoetz@gmail.com>)
# Cookbook Name:: java-libraries
# Provider:: certificate
#
# Copyright 2013, Mevan Samaratunga
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

require "digest/sha2"
require "fileutils"

class Chef::Provider::JavaCertificate < Chef::Provider::LWRPBase  

  action :install do
      
      java_home = get_java_home
      keytool = build_keytool_path

      truststore = new_resource.keystore_path
      truststore_passwd = new_resource.keystore_passwd
      
      truststore = "#{java_home}/jre/lib/security/cacerts" if truststore.nil?
      truststore_passwd = "changeit" if truststore_passwd.nil?

      certalias = new_resource.cert_alias
      certalias = new_resource.name if certalias.nil?

      certdata = new_resource.cert_data
      certdatafile = new_resource.cert_file
      certendpoint = new_resource.ssl_endpoint
      
      if certdata.nil?
              
          if !certdatafile.nil?
              
              certdata = IO.read(certdatafile)
              
          elsif !certendpoint.nil?
              
              result = `echo QUIT | openssl s_client -showcerts -connect #{certendpoint}`
              Chef::Log.debug("Executing: echo QUIT | openssl s_client -showcerts -connect #{certendpoint}\n#{result}")
              
              if $?.success?
                  certout = result.split(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----/)
                  if certout.size > 2 && !certout[1].empty?
                      certdata = "-----BEGIN CERTIFICATE-----#{certout[1]}-----END CERTIFICATE-----"
                  else
                      Chef::Application.fatal!("Unable to parse certificate from openssl query of #{certendpoint}.", 999)
                  end
              else
                  Chef::Application.fatal!("Error returned when attempting to retrieve certificate from remote endpoint " \
                      "#{certendpoint}: #{$?}", $?.to_s[/exit (\d+)/, 1].to_i)
              end
          else
              Chef::Application.fatal!("At least one of cert_data, cert_file or ssl_endpoint attributes must be provided.", 999)
          end
      end
      
      hash = Digest::SHA512.hexdigest(certdata)
      certfile = build_cert_file_path(certalias, truststore, hash)
      unless ::File.exists?(certfile)
          
          result = `#{keytool} -list -keystore #{truststore} -storepass #{truststore_passwd} -v`
          Chef::Log.debug("Executing: #{keytool} -list -keystore #{truststore} -storepass #{truststore_passwd} -v | grep \"#{certalias}\"\n#{result}")
          Chef::Application.fatal!("Error querying keystore for existing certificate: #{$?}", $?.to_s[/exit (\d+)/, 1].to_i) unless $?.success?
          
          has_key = !result[/Alias name: #{certalias}/].nil?
          
          if has_key
              
              result = `#{keytool} -delete -alias \"#{certalias}\" -keystore #{truststore} -storepass #{truststore_passwd}`            
              Chef::Log.debug("Executing: #{keytool} -delete -alias \"#{certalias}\" -keystore #{truststore} -storepass #{truststore_passwd}\n#{result}")
              Chef::Application.fatal!("Error deleting existing certificate \"#{certalias}\" in " \
                  "keystore so it can be updated: #{$?}", $?.to_s[/exit (\d+)/, 1].to_i) unless $?.success? 
          end
          
          ::File.open(certfile, "w", 0644) { |f| f.write(certdata) }
          
          result = `#{keytool} -import -trustcacerts -alias \"#{certalias}\" -file #{certfile} -keystore #{truststore} -storepass #{truststore_passwd} -noprompt`
          Chef::Log.debug("Executing: #{keytool} -import -trustcacerts -alias \"#{certalias}\" -file #{certfile} " \
              "-keystore #{truststore} -storepass #{truststore_passwd} -noprompt\n#{result}")
          
          unless $?.success?
              
              FileUtils.rm_f(certfile)
              Chef::Application.fatal!("Error importing certificate into keystore: #{$?}", $?.to_s[/exit (\d+)/, 1].to_i) 
          end
          
          Chef::Log.debug("Sucessfully imported certificate \"#{certalias}\" to keystore \"#{truststore}\".")
      else
          Chef::Log.debug("Certificate \"#{certalias}\" in keystore \"#{truststore}\" is up-to-date.")
      end
      
  end

  action :remove do
      
      certalias = new_resource.name
      java_home = get_java_home
      keytool = build_keytool_path

      truststore = new_resource.keystore_path
      truststore_passwd = new_resource.keystore_passwd
      
      truststore = "#{java_home}/jre/lib/security/cacerts" if truststore.nil?
      truststore_passwd = "changeit" if truststore_passwd.nil?
          
      keytool = "#{java_home}/bin/keytool"

      has_key = !`#{keytool} -list -keystore #{truststore} -storepass #{truststore_passwd} -v | grep "#{certalias}"`[/Alias name: #{certalias}/].nil?
      Chef::Application.fatal!("Error querying keystore for existing certificate: #{$?}", $?.to_s[/exit (\d+)/, 1].to_i) unless $?.success?
      
      if has_key
          
          `#{keytool} -delete -alias \"#{certalias}\" -keystore #{truststore} -storepass #{truststore_passwd}`            
          Chef::Application.fatal!("Error deleting existing certificate \"#{certalias}\" in " \
              "keystore so it can be updated: #{$?}", $?.to_s[/exit (\d+)/, 1].to_i) unless $?.success? 
      end
      
      certfile = build_cert_file_path(certalias, truststore, "*")
      FileUtils.rm_f(certfile)
      
  end

  # Build the path of the keytool command based on the JAVA HOME.
  #
  # On windows, this path is surrounded by double quotes
  # in order to take care of white spaces (C:/Program Files/...).
  #
  # @return String The keytool path.
  def build_keytool_path
    keytool = ::File.join(get_java_home, "/bin/keytool")
    if platform_family?("windows")
      keytool = %Q{"#{keytool}"}
    else 
      keytool
    end
  end

  # Return the JAVA HOME path considering first the java_home resource attribute
  #  then the ['java']['java_home'] node attribute.
  #
  # return [String] The JAVA HOME path. 
  def get_java_home
    new_resource.java_home || node['java']['java_home']
  end

  # Build the certificate file path under the Chef cache directory.
  # @param [String] cert_alias Certificate alias.
  # @param [String] truststore Truststore path.
  # @param [String] hash Certificate content hash.
  # @return [String] The certificate file path.
  def build_cert_file_path(cert_alias, truststore, hash)
    sanitized_truststore = truststore.gsub(%r{[:'"]}, "").gsub(%r{[ /\\\.]}, "_")
    "#{Chef::Config[:file_cache_path]}/#{cert_alias}-#{sanitized_truststore}.cert.#{hash}"
  end
end
