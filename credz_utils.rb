#!/usr/bin/env ruby

require 'debug_utils'
require 'password_utils'
require 'sqlite3'
require 'optparse'
require 'ffi'
require 'json'
require 'nokogiri'

$debug = false




module Credentials

module NSS
  extend FFI::Library
  ffi_lib 'nss3'

  enum :secStatus, [
                    :secWouldBlock, -2,
                    :secFailure,
                    :secSuccess
                   ]

  enum :secItemType, [
                      :siBuffer, 0,
                      :siClearDataBuffer,
                      :siCipherDataBuffer,
                      :siDERCertBuffer,
                      :siEncodedCertBuffer,
                      :siDERNameBuffer,
                      :siEncodedNameBuffer,
                      :siAsciiNameString,
                      :siAsciiString,
                      :siDEROID,
                      :siUnsignedInteger,
                      :siUTCTime,
                      :siGeneralizedTime,
                      :siVisibleString,
                      :siUTF8String,
                      :siBMPString
                     ]

  class SECItem < FFI::Struct
    layout :type, :secItemType,
           :data, :pointer,
           :len,  :int
  end

  attach_function :NSS_Init, [ :string ], :int
  attach_function :PK11_GetInternalKeySlot, [ ], :pointer
  attach_function :PK11_CheckUserPassword, [ :pointer , :string ], :secStatus
  attach_function :PK11_Authenticate, [ :pointer, :int, :pointer ], :int
  attach_function :PK11SDR_Decrypt, [ :pointer, :pointer, :pointer ], :int
end

module Decrypt

class Default

  def parse(input, type)
    if type == :file
      parse_file(input)
    elsif type == :string
      parse_string(input)
    end
  end

  def parse_file(input)
  end

  def parse_string(input)
  end

end

class UVNC < Default

  def parse_file(input)
    f = open(input, 'r')
    f.readlines.each do |line|
      if line.start_with? "passwd"
        parse_string(line.strip.split("=")[1][0..15])
      end
    end
  end

  def parse_string(input)
    print_info "#{Password::VNC.decrypt(input.unhex)} (#{input})"
  end

end

# Good read => http://www.infond.fr/2010/04/firefox-passwords-management-leaks.html
class Firefox < Default

  def decrypt(source, hostname, encryptedUsername, encryptedPassword)

    enc_username = NSS::SECItem.new
    enc_password = NSS::SECItem.new
    dec_username = NSS::SECItem.new
    dec_password = NSS::SECItem.new

    enc_username[:data] = FFI::MemoryPointer.from_string(encryptedUsername.base64_decode)
    enc_username[:len]  = encryptedUsername.base64_decode.length

    enc_password[:data] = FFI::MemoryPointer.from_string(encryptedPassword.base64_decode)
    enc_password[:len]  = encryptedPassword.base64_decode.length

    if NSS.PK11SDR_Decrypt(enc_username, dec_username, nil) == -1
      print_debug "PK11SDR_Decrypt failed for username"
    end

    if NSS.PK11SDR_Decrypt(enc_password, dec_password, nil) == -1
      print_debug "PK11SDR_Decrypt failed for password"
    end

    username = dec_username[:data].read_string()[0..dec_username[:len] -1]
    password = dec_password[:data].read_string()[0..dec_password[:len] -1]
    if $debug
      print_info "#{source} => #{hostname} -- #{username} -- #{password}"
    else
      print_info "#{hostname} -- #{username} -- #{password}"
    end

  end

  def parse(input, type)
    unless type == :dir
      print_error "#{input} type (#{type}) is not 'dir'"
    end

    unless NSS.NSS_Init(input) == 0
      print_debug "Failed at reading #{input}"
      return
    end

    keySlot = NSS.PK11_GetInternalKeySlot()
    NSS.PK11_CheckUserPassword(keySlot, "")
    NSS.PK11_Authenticate(keySlot, 1, nil)

    db_path = "#{input}/signons.sqlite"
    if File.exists? db_path

      print_debug "#{input}/signons.sqlite exists"
      db = SQLite3::Database.new( db_path )
      ff_credz = db.execute("SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins ORDER BY hostname")
      ff_credz.each do |hostname, encryptedUsername, encryptedPassword|
        self.decrypt(db_path, hostname, encryptedUsername, encryptedPassword)
      end
      db.close

    else
      print_debug "#{input}/signons.sqlite does not exists"
      return
    end

    db_path = "#{input}/logins.json"
    if File.exists? db_path

      print_debug "#{input}/logins.json exists"
      db = File.open( db_path )
      json = JSON.parse( db.read )

      json["logins"].sort{|a,b| a["hostname"] <=> b["hostname"]}.each do |login|
        self.decrypt(db_path, login["hostname"], login["encryptedUsername"], login["encryptedPassword"])
      end

    end

  end

end

class FileZilla < Default

  @@files = [ "sitemanager.xml", "filezilla.xml" ]

  def parse(input, type)

    case type

    when :file
      parse_file(input)
    when :dir
      parse_dir(input)
    else
      print_error "Filezilla - #{input} type (#{type}) is not supported"
    end

  end

  def parse_dir(input)

    @@files.each do |f|
      parse_file("#{input}/#{f}")
    end

  end

  def parse_file(input)

    return File.exist?(input)

    case File.basename(input)

    when "sitemanager.xml"
      f = File.open( input )
      xml = Nokogiri::XML( f )

      servers = xml.xpath("//FileZilla3/Servers/Server")
      servers.each do |server|

        host = server.xpath("Host").text
        port = server.xpath("Port").text
        user = server.xpath("User").text
        pass = server.xpath("Pass").text

        print_info "#{host}:#{port} => #{user} - #{pass}"

      end
      f.close

    when "filezilla.xml"
      f = File.open( input )
      xml = Nokogiri::XML( f )

      host = xml.xpath("//FileZilla3/Settings/Setting[@name='FTP Proxy host']")[0].text
      user = xml.xpath("//FileZilla3/Settings/Setting[@name='FTP Proxy user']")[0].text
      pass = xml.xpath("//FileZilla3/Settings/Setting[@name='FTP Proxy password']")[0].text

      unless ( host.nil? or host.length == 0 ) and
             ( user.nil? or user.length == 0 ) and
             ( pass.nil? or pass.length == 0 )
        print_info "#{host} => #{user} - #{pass}"
      end

      host = xml.xpath("//FileZilla3/Settings/Setting[@name='Proxy host']")[0].text
      port = xml.xpath("//FileZilla3/Settings/Setting[@name='Proxy port']")[0].text
      user = xml.xpath("//FileZilla3/Settings/Setting[@name='Proxy user']")[0].text
      pass = xml.xpath("//FileZilla3/Settings/Setting[@name='Proxy password']")[0].text

      unless ( host.nil? or host.length == 0 ) and
             ( port.nil? or port.length == 0 or port == "0" ) and
             ( user.nil? or user.length == 0 ) and
             ( pass.nil? or pass.length == 0 )
        print_info "#{host}:#{port} => #{user} - #{pass}"
      end

      f.close

    end

  end

end

end

end

if $0 == __FILE__

  options = {
    :input => [],
  }

  opts = OptionParser.new
  opts.banner = "Usage: #{$0} -f <format> -t <input-type> -i <input> [options]"

  opts.on("-f", "--format FORMAT", "The format to be read") do |f|
    case f.downcase
    when "uvnc"
      options[:format] = Credentials::Decrypt::UVNC
    when "ultravnc"
      options[:format] = Credentials::Decrypt::UVNC
    when "ff"
      options[:format] = Credentials::Decrypt::Firefox
    when "firefox"
      options[:format] = Credentials::Decrypt::Firefox
    when "filezilla"
      options[:format] = Credentials::Decrypt::FileZilla
    else
      print_error "Unknown format #{f}"
      puts opts.banner
      exit
    end
  end

  opts.on("-i", "--input INPUT", "The input would usually be some string(s) of file(s)") do |i|
    options[:input] << i
  end

  opts.on("-t", "--type TYPE", "Specify if input will be string(s) or file(s)") do |t|
    case t.downcase
    when "string"
      options[:type] = :string
    when "file"
      options[:type] = :file
    when "dir"
      options[:type] = :dir
    else
      print_error "Unknown type #{t}"
      puts opts.banner
      exit
    end
  end

  opts.on("-o", "--output OUTPUT", "The sqlite3 file you want to put the credz on") do |o|
    options[:output] = o
  end

  opts.on("-d", "--debug") do
    $debug = true
  end

  opts.parse!

  parser = options[:format].new()
  options[:input].each do |input|
    puts "Processing #{input}" if $debug
    parser.parse(input, options[:type])
  end

end
