#!/usr/bin/env ruby

require 'debug_utils'
require 'metasm'
require 'uri'

if RUBY_VERSION >= "1.9.0"
  ZEROBYTE = "\x00".force_encoding(Encoding::BINARY)  unless defined? ZEROBYTE
else # older Ruby versions:
  ZEROBYTE = "\0"  unless defined? ZEROBYTE
end


class Array
  def iterate_parallel
    temp = map { |e| e.to_enum }
    loop do
      yield temp.map { |e| e.next }
    end
  end

  def iterate_all
    temp = map { |e| e.to_enum }
    begin
      yield temp.map { |e| e.peek }
    rescue StopIteration
      return nil
    end
    loop do
      temp.reverse_each.with_index(1) do |e, i|
        begin
          e.next
          yield temp.map { |e| e.peek }
          break
        rescue StopIteration
          if i == temp.length
            raise StopIteration
          end
          e.rewind
        end
      end
    end
  end
end

class String

  if RUBY_VERSION >= "1.9.0"

    alias bytesize size

    def getbyte(x)   # when accessing a string and selecting x-th byte to do calculations , as defined in Ruby 1.9
      self[x]        # returns an integer
    end

    # def unhexify()
    #   [ self ].pack("m0*")
    # end

  else # older Ruby versions:

    # def unhexify()
    #   [ self ].pack("m0*").delete("\n")
    # end

  end

  def hex?()
    (self =~ /^[a-f0-9]+$/i)? true : false
  end

  def url?()
    res = self =~ /\A#{URI::regexp(['http', 'https'])}\z/
    res == nil ? false : true
  end


  def mac2ipv6()

    macsplit = self.split(':')

    macsplit.insert(3, "fe")
    macsplit.insert(3, "ff")

    macsplit[0] = (macsplit[0].to_i(16) ^ 2).to_s(16)
    macsplit.map!{|x| x.upcase}
    "FE80::#{macsplit[0..1].join}:#{macsplit[2..3].join}:#{macsplit[4..5].join}:#{macsplit[6..7].join}"

  end

  ###  def hexdump(opt={})
  ###    s=self
  ###    out = opt[:out] || StringIO.new
  ###    len = (opt[:len] and opt[:len] > 0)? opt[:len] + (opt[:len] % 2) : 16
  ###
  ###    off = opt[:start_addr] || 0
  ###    offlen = opt[:start_len] || 8
  ###
  ###    hlen=len/2
  ###
  ###    s.scan(/(?:.|\n){1,#{len}}/) do |m|
  ###      out.write(off.to_s(16).rjust(offlen, "0") + '  ')
  ###
  ###      i=0
  ###      m.each_byte do |c|
  ###        out.write c.to_s(16).rjust(2,"0") + " "
  ###        out.write(' ') if (i+=1) == hlen
  ###      end
  ###
  ###      out.write("   " * (len-i) ) # pad
  ###      out.write(" ") if i < hlen
  ###
  ###      out.write(" |" + m.tr("\0-\37\177-\377", '.') + "|\n")
  ###      off += m.length
  ###    end
  ###
  ###    out.write(off.to_s(16).rjust(offlen,'0') + "\n")
  ###
  ###    if out.class == StringIO
  ###      out.string
  ###    end
  ###  end
  ###
  ###  def unhexdump(opt={})
  ###    s=self
  ###    out = opt[:out] || StringIO.new
  ###    len = (opt[:len] and opt[:len] > 0)? opt[:len] : 16
  ###
  ###    hcrx = /[A-Fa-f0-9]/
  ###    dumprx = /^(#{hcrx}+):?\s*((?:#{hcrx}{2}\s*){0,#{len}})/
  ###    off = opt[:start_addr] || 0
  ###
  ###    i=1
  ###    # iterate each line of hexdump
  ###    s.split(/\r?\n/).each do |hl|
  ###      # match and check offset
  ###      if m = dumprx.match(hl) and $1.hex == off
  ###        i+=1
  ###        # take the data chunk and unhexify it
  ###        raw = $2.unhexify
  ###        off += out.write(raw)
  ###      else
  ###        raise "Hexdump parse error on line #{i} #{s}"
  ###      end
  ###    end
  ###
  ###    if out.class == StringIO
  ###      out.string
  ###    end
  ###  end
  ###  # alias_method :undump, :unhexdump

  def to_shellcode()
    self.each_byte.map {|x| "\\x%02x" % x.ord.to_i}.join()
  end

  def to_mysql()
    # Convert string to MySQL CHAR()
    "CHAR(" + self.each_byte.map {|x| x.ord }.join(',') + ")"
  end

  def to_mssql()
    # Convert string to MS-SQL CHAR()
    self.each_byte.map {|x| "CHAR(#{x.ord})" }.join('+')
  end

  def assemble(arch=Metasm::X86)
    puts Metasm::Shellcode.assemble(arch.new, self.gsub(";", "\n")).encode_string.to_shellcode()

  end

  def disassemble(arch=Metasm::X86)
    puts Metasm::Shellcode.disassemble(arch.new, self).to_s.gsub(/^$\n/, '')
  end

  def run_assembly(arch=Metasm::X86)
    puts "That bitchy function doesn't work yet"
  end

  def to_js()
    "String.fromCharCode(" + self.each_byte.map {|x| x.ord }.join(',') + ")"
  end

end

class Fixnum

  def to_signed(bits=32)
    return self if self < (1 << bits)/2

    (~((1<<(bits - 1)) - (self % (1<<(bits - 1)))) + 1)
  end

end

module Gul
  class Oracle
    def self.vsnnum_to_s(vsn)
        vsn.to_s(16).gsub(/0+/, '0').each_byte.map{|x| x.chr.hex}.join('.')
    end
  end

  class ViewState

    def viewstate?(str)

      res = false
      begin

        res = str.base64_decode
        res = true if str.starts_with? "\xff\x01"

      rescue
      end
      res
    end

    # TODO :p
    # def decode(str)
    #   return nil unless ViewState::viewstate?(str)
    # end

  end

  class URL

    def self.hashify(urls)
      hlist = {}

      urls.each do |url|
	begin
	  uri = URI.parse(url)
	rescue
	  print_debug "Failed to parse: #{url}"
	  next
	end

	hlist[uri.host] = {} unless hlist.include?(uri.host)
	vhost = hlist[uri.host]

	vhost[uri.path] = {} unless vhost.include?(uri.path)
	path = vhost[uri.path]

	unless uri.query.nil?
	  cgi = CGI.parse(uri.query)
	  cgi.each_pair do |param, value|
	    unless param.nil? or value.nil?
	      path[param] = []       if     path[param].nil?
	      path[param].push value unless path[param].include? value
	      path[param].sort!
	    end
	  end
	end
      end
      hlist
    end

    def self.print_synthesis(urls)

      hlist = URL.hashify(urls)

      hlist.keys.sort.each do |vhost|
	print_info blue(vhost)
	hlist[vhost].keys.sort.each do |path|
	  unless hlist[vhost][path].nil? or hlist[vhost][path].keys.nil?
	    param_list = hlist[vhost][path].keys.sort!.join(', ')
	    param_list = "(#{param_list})" unless param_list.length() == 0
	    print_info "    #{green(path)} #{param_list}"
	    hlist[vhost][path].keys.sort.each do |param|
	      print_info " -- -- #{red(param)} => #{hlist[vhost][path][param].join(', ')}"
	    end
	  end
	end
      end
      true
    end # Gul::URL.print_synthesis

  end # Gul::URL

end # Gul

