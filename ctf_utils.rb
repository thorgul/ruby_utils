#!/usr/bin/env ruby

require 'crypto_utils'

require 'zlib'
require 'uri'
require 'mini_exiftool'
require 'mime-types'
require 'net/http'
require 'net/http/post/multipart'
require 'nokogiri'

class String

  def include_only?(charset)
    self.each_char do |c|
      return false unless charset.include? c
    end
    true
  end

  def is_gzip?()
    return false if self[0..1].force_encoding(Encoding::BINARY) != "\x1f\x8b".force_encoding(Encoding::BINARY)
    true
  end

  def is_base64?()
    if self.base64_decode.length == 0 or
        self.downcase.delete("a-z0-9/=").length > 0
      return false
    end
    true
  end

  def is_uri_encoded?()
    return false if self.match(/%[0-9a-fA-F][0-9a-fA-F]/).nil?
    true
  end

end

module CTF

  def self.decode_string(str, decoder=[])
    str.strip!
    res = str
    if str.include_only? "01"
      res = str.unbin
    elsif str.downcase.include_only? "0123456789abcdef"
      res = str.unhex
    elsif str.is_gzip?
      res = Zlib::GzipReader.new(StringIO.new(str)).read
    elsif str.is_base64?
      res = str.base64_decode
    elsif str.is_uri_encoded?
      res = URI.decode str
    elsif str.starts_with? "\xff\x01"
      puts "That shit is a ViewState"
    end


    decoder.each do |d|
      if d[:match].call str
        res = d[:decode].call str
        break
      end
    end

    if res and res != str
      res = decode_string(res, decoder)
    end

    res
  end

  class TinEye

    def self.analyse(path)

      res = nil
      orig_path = nil
      url = URI.parse('http://tineye.com/search')
      exif = MiniExiftool.new(path)
      imagewidth = exif.imagewidth
      imageheight = exif.imageheight

      File.open(path) do |f|

        mime_type = MIME::Types.type_for(path)[0]
        mime_type = MIME::Types["application/octet-stream"][0] if mime_type.nil?

        upfile = UploadIO.new(f, mime_type, path)

        req = Net::HTTP::Post::Multipart.new(url.path, "image" => upfile)
        res = Net::HTTP.start(url.host, url.port) { |http| http.request(req) }
      end

      while res.class == Net::HTTPRedirection or
          ( res.class == Net::HTTPFound and !res['location'].nil? )
        url = URI.parse(res['location'])
        puts "==> #{url.to_s}"
        req = Net::HTTP::Get.new(url.path)
        res = Net::HTTP.start(url.host, url.port) { |http| http.request(req) }
      end
      res

      html_doc = Nokogiri::HTML(res.body)

      html_doc.xpath("//div[@class='search-results-item-image']").each do |d|
        width  = d.xpath("div/a/img/@width").text.to_i
        height = d.xpath("div/a/img/@height").text.to_i
        if [ imagewidth, imageheight ] == [ width, height ]
          orig_path = d.xpath("div/a/img/@src").text
          break
        end
      end

      if orig_path.nil?
        html_doc.xpath("//div[@class='search-content-results-header-image']").each do |d|
          width, height = d.xpath("div/p").text.split(',')[1].strip.split("x")
          width = width.to_i
          height = height.to_i
          if [ imagewidth, imageheight ] == [ width, height ]
            orig_path = d.xpath("div/img/@src").text
            break
          end
        end
      end

      unless orig_path.nil?
        puts "Original image found at #{orig_path}"
        orig_url = URI.parse(orig_path)
        orig_req = Net::HTTP::Get.new(orig_url.path)
        orig_res = Net::HTTP.start(orig_url.host, orig_url.port) { |http| http.request(orig_req) }
        f = File.open("#{path}.orig", 'w')
        f.write(orig_res.body)
        f.close

        orig_exif = MiniExiftool.new("#{path}.orig")
        orig_size = File.size("#{path}.orig")
        size = File.size(path)

        if orig_size != size
          puts "Original file size is #{orig_size} while provided file size is #{size}"
        end
      end

    end
  end


end
