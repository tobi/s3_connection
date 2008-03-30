require 'net/http'
require 'time'
require 'openssl'
require 'base64'
require 'cgi'

module S3

  class ConnectionError < StandardError
  end

  class Connection 
    cattr_accessor :debug
    AmazonPrefix = /^x\-amz\-/io
  
  
    def initialize(access_key, access_secret, bucket, host = "s3.amazonaws.com")       
      @access_key, @access_secret, @bucket,  @host = access_key, access_secret, bucket, host
    end                 
  
    def put(key, data, options = {})
      request(:put, key, data, options) 
    end
  
    def post(key, data, options = {})   
      request(:post, key, data, options)
    end  
  
    def get(key)   
      request(:get, key)
    end   
    
    def head(key)
      request(:head, key)
    end             
  
    def delete(key)
      request(:delete, key)
    end
  
    private    
  
    def request(verb, key, data = nil, options = {})                
      http.start unless http.started?

      path = File.join(@bucket, key)
        
      response = retry_on_stale_connection do                                        
        action = request_method(verb).new("/#{path}")                   
        action['Host'] = @host
        action['Date'] = Time.now.httpdate
    
        if data             
          action['Content-Type'] = mime_type_for(key)

          if data.respond_to?(:read)                                                                
            action.body_stream    = data                                                           
            action.content_length = data.respond_to?(:lstat) ? data.lstat.size : data.size         
          else
            action.body = data
            action.content_length  = data.size.to_s            
          end
        end         
                    
        if action.method == 'PUT'
          action['x-amz-acl'] = options[:access] || 'public-read'
        end
    
        action['Authorization'] = permission_for(action)        
    
        http.request(action)
      end

      raise ConnectionError, "Http error #{response.code}: #{response.message} #{response.body}" unless response.code == '200'   
                   
      if response['Content-Type'] == 'application/xml'
        XmlNode.parse(response.body)
      else
        response.body
      end
    end      
  
    def request_method(verb)
      Net::HTTP.const_get(verb.to_s.capitalize)
    end   
  
    def mime_type_for(key)
      MIME::Types.type_for(key).first
    rescue => e 
      $stderr << e
      'text/plain'
    end
  
    def http
      @http ||= begin
        net = Net::HTTP.new(@host) 
        net.set_debug_output $stderr if debug
        net
      end    
    end  
  
    def retry_on_stale_connection
      yield
    end    
  
    def permission_for(request)                     
      digest   = OpenSSL::Digest::Digest.new('sha1')

      cannonical_string = "#{request.method}\n#{request['Content-MD5']}\n#{request['Content-Type']}\n#{request['Date']}\n#{interesting_headers(request)}#{request.path}"
    
      b64_hmac = Base64.encode64(OpenSSL::HMAC.digest(digest, @access_secret, cannonical_string)).strip                                                                             
    
      "AWS #{@access_key}:#{b64_hmac}"
    end
  
    def interesting_headers(request)    
      cannonical_headers = [] 
      request.each do |key, value|  
        next unless key =~ AmazonPrefix
        cannonical_headers << "#{key}:#{value}"
      end          
      cannonical_headers.sort.map { |h| h + "\n"}
    end  
  end

end