#!/usr/bin/env ruby

require 'nokogiri'
require 'sqlite3'
require 'optparse'
require 'zip'

module Gul

module Scan

  def self.xpath_attr(opts)

    return "" if opts[:xpath].nil? or opts[:attr].nil? or opts[:attr] == ""
    return "" if opts[:xpath].class == Nokogiri::XML::NodeSet and  opts[:xpath].length == 0

    attr = opts[:xpath].attr(opts[:attr]).to_s
    attr = opts[:header].to_s + attr + opts[:trailer].to_s unless attr == ""
    attr

  end

class Generic

  # File.basename(xmlpath, File.extname(xmlpath)) + ".sqlite"
  def initialize(path)

    @db = SQLite3::Database.new( path )

    @db.execute( "CREATE TABLE IF NOT EXISTS host_info (      " +
                 "  id    INTEGER PRIMARY KEY AUTOINCREMENT,  " +
                 "  ip    VARCHAR(15),                        " +
                 "  title TEXT,                               " +
                 "  data  TEXT )                              " )
    @db.execute( "CREATE TABLE IF NOT EXISTS port_info (      " +
                 "  id      INTEGER PRIMARY KEY AUTOINCREMENT," +
                 "  ip      VARCHAR(15),                      " +
                 "  port    SMALLINT,                         " +
                 "  service TEXT )                            " )
    @db.execute( "CREATE TABLE IF NOT EXISTS service_info (   " +
                 "  id     INTEGER,                           " +
                 "  source TEXT,                              " +
                 "  title  TEXT,                              " +
                 "  data   TEXT )                             " )
  end

  def insert_host_values(values=nil)

    false if values.nil?

    preped = @db.prepare( "INSERT INTO host_info " +
                          "SELECT NULL, ?, ?, ?  " +
                          "WHERE  NOT EXISTS (   " +
                          "  SELECT 1            " +
                          "  FROM host_info      " +
                          "  WHERE ip    = ? AND " +
                          "        title = ? AND " +
                          "        data  = ? )   " )

    values.each_pair {|k,v| values[k] = v.strip if v.class == String }
    preped.bind_params( values[:ip],
                        values[:title],
                        values[:data],
                        values[:ip],
                        values[:title],
                        values[:data] )
    preped.execute!
    preped.close
    true
  end

  def insert_port_values(values=nil)

    false if values.nil?

    values.each_pair {|k,v| values[k] = v.strip if v.class == String }
    preped = @db.prepare( "INSERT INTO port_info    " +
                          "SELECT NULL, ?, ?, ?     " +
                          "WHERE NOT EXISTS (       " + 
                          "  SELECT 1               " +
                          "  FROM port_info         " +
                          "  WHERE ip      = ?  AND " +
                          "        port    = ?  AND " +
                          "        service = ? )"     )
    preped.bind_params( values[:host],
                        values[:port],
                        values[:service],
                        values[:host],
                        values[:port],
                        values[:service])
    preped.execute!
    preped.close
    true
  end

  def insert_service_values(values=nil)

    false if values.nil?

    values.each_pair {|k,v| values[k] = v.strip if v.class == String }
    preped = @db.prepare( "INSERT INTO service_info  " +
                          "SELECT ?, ?, ?, ?         " +
                          "WHERE NOT EXISTS (        " +
                          "  SELECT 1                " +
                          "  FROM service_info       " +
                          "  WHERE id     = ?    AND " +
                          "        source = ?    AND " +
                          "        title  = ?    AND " +
                          "        data   = ? )      " )
    preped.bind_params( values[:id],
                        values[:source],
                        values[:title],
                        values[:data],
                        values[:id],
                        values[:source],
                        values[:title],
                        values[:data]  )
    preped.execute!
    preped.close
    true
  end


  def get_service_id(values=nil)

    return nil if values.nil?

    id = @db.get_first_value( "SELECT id            " +
                              "FROM port_info       " +
                              "WHERE ip   = ?  AND  " +
                              "      port = ?",
                             values[:host],
                             values[:port]            )

    return id unless id.nil?
    return id if values[:create] == false

    values[:create] = false
    insert_port_values(values)

    return get_service_id(values)

  end

  def parse(path)
    self.xml2sql(path)
  end

  def xml2sql(xmlpath)

    unless File.exists?(xmlpath)
      puts "#{xmlpath} does not exists"
      return
    end

    @f = File.open( xmlpath )
    @xml = Nokogiri::XML( @f )

    if @xml.nil?
      puts "#{xmlpath} is not a valid xml file"
      return
    end

  end

  def close()
    @db.close
    @f.close
  end

end

class Nmap < Generic

  def xml2sql(xmlpath)

    super

    open_ports = @xml.xpath("//host/ports/port/state[@state='open']")

    if open_ports.nil? or open_ports.length == 0
      puts "#{xmlpath}: No open ports"
      return
    end

    @db.execute("BEGIN TRANSACTION")


    @xml.xpath("//host/address[@addrtype='ipv4']").each do |xhost|
      ipv4 = Gul::Scan::xpath_attr(:xpath => xhost, :attr => "addr")

      xhost.parent.xpath("address").each do |addr|
        insert_host_values(:ip    => ipv4,
                           :title => "address:" + Gul::Scan::xpath_attr(:xpath => addr, :attr => "addrtype"),
                           :data  =>              Gul::Scan::xpath_attr(:xpath => addr, :attr => "addr"))
      end

      xhost.parent.xpath("hostnames/hostname").each do |hostname|
        insert_host_values(:ip    => ipv4,
                           :title => "hostname:" + Gul::Scan::xpath_attr(:xpath => hostname, :attr => "type"),
                           :data  =>               Gul::Scan::xpath_attr(:xpath => hostname, :attr => "name"))
      end

    end

    open_ports.each do |open|

      port = open.parent
      host = port.parent.parent

      next if port.nil?
      next if host.nil?

      xservice = port.xpath("service")
      xhost    = host.xpath("address[@addrtype='ipv4']")

      s_service =  Gul::Scan::xpath_attr(:xpath => xservice, :attr => "name")
      s_service << Gul::Scan::xpath_attr(:xpath => xservice, :attr => "product",   :header => " / ")
      s_service << Gul::Scan::xpath_attr(:xpath => xservice, :attr => "version",   :header => " / ")
      s_service << Gul::Scan::xpath_attr(:xpath => xservice, :attr => "extrainfo", :header => " / ")

      s_host = Gul::Scan::xpath_attr(:xpath => xhost, :attr => "addr")
      s_port = Gul::Scan::xpath_attr(:xpath => port,  :attr => "portid")

      id = get_service_id(:host    => s_host,
                          :port    => s_port,
                          :service => s_service,
                          :create  => true)

      xscripts = port.xpath("script")
      xscripts.each do |script|

        title = Gul::Scan::xpath_attr(:xpath => script, :attr => "id")
        data  = Gul::Scan::xpath_attr(:xpath => script, :attr => "output")

        insert_service_values(:id     => id,
                              :source => "nmap",
                              :title  => title,
                              :data   => data )

      end

    end

    @db.execute("END TRANSACTION")

  end
end

class Burp < Generic

  def parse(path)
    self.burp2sql(path)
  end

  def burp2sql(path)

    @f = Zip::File.open(path)

    @f.each do |entry|

      xml = entry.get_input_stream.read

      xml.scan(/<issue>.*?<host>(.*?)<\/host>.*?<port>(.*?)<\/port>.*?<(http.?)>.*?<id>(.*?)<\/id>.*?<\/issue>/m).each do |m|

        s_host    = m[0][5..-1]
        s_port    = m[1].unpack('H*')[0].to_i(16)
        s_service = m[2]
        s_data    = m[3][5..-1].gsub(/<\/?.*?>/m, "")

        id = get_service_id(:host    => s_host,
                            :port    => s_port,
                            :service => s_service,
                            :create  => true)

        insert_service_values(:id     => id,
                              :source => "burp",
                              :title  => "issue",
                              :data   => s_data )

      end

    end

  end

end


class Nikto < Generic

  def xml2sql(xmlpath)

    super

    items = @xml.xpath("//niktoscan/scandetails/item")
    s_host = Gul::Scan::xpath_attr(:xpath => @xml.xpath("//niktoscan/scandetails"), :attr => "targetip")
    s_port = Gul::Scan::xpath_attr(:xpath => @xml.xpath("//niktoscan/scandetails"), :attr => "targetport")

    if items.nil? or items.length == 0
      puts "#{xmlpath}: No items found"
      return
    end

    if s_host.nil? or s_port.nil?
      puts "#{xmlpath}: Failed to validate host (#{s_host}) / port (#{s_port})"
      return
    end

    @db.execute("BEGIN TRANSACTION")

    id = get_service_id( :host   => s_host,
                         :port   => s_port,
                         :create => true)

    items.each do |item|

      insert_service_values( :id     => id,
                             :source => "nikto",
                             :title  => item.xpath("namelink").text,
                             :data   => item.xpath("description").text )
    end

    @db.execute("END TRANSACTION")
  end

end


class Ettercap < Generic

  def xml2sql(xmlpath)

    if File.exists?(xmlpath)
      tmp = File.open( xmlpath )

      line = ""
      line = tmp.readline.chomp while line == ""

      if line.start_with? "\x1b\x5b\x31\x6d\x65\x74\x74\x65\x72"
        while line == ""  or
            line.start_with? "\x1b\x5b\x31\x6d\x65\x74\x74\x65\x72"
          line = tmp.readline.chomp
        end

        f = File.open( ".scan_utils.tmp", mode="w" )
        f.write line + "\n"
        f.write tmp.read
        f.close

        xmlpath = ".scan_utils.tmp"
      end

      tmp.close
    end

    super

    if @xml.nil?
      puts "#{xmlpath} is not a valid xml file"
      return
    end

    hosts = @xml.xpath("//etterlog/host")

    if hosts.nil? or hosts.length == 0
      puts "#{xmlpath}: No host found"
      return
    end

    @db.execute("BEGIN TRANSACTION")

    hosts.each do |host|

      ipv4 = Gul::Scan::xpath_attr(:xpath => host, :attr => "ip")
      insert_host_values(:ip    => ipv4,
                         :title => "address:ipv4",
                         :data  => ipv4)

      hostname = host.xpath("hostname").text
      unless hostname.length == 0
        insert_host_values(:ip    => ipv4,
                           :title => "hostname:PTR",
                           :data  => hostname)
      end

      ostype = host.xpath("os").text
      unless ostype.length == 0
        insert_host_values(:ip    => ipv4,
                           :title => "os:type",
                           :data  => ostype)
      end

      host.xpath("port").each do |port|

        s_port  = Gul::Scan::xpath_attr(:xpath => port, :attr => "addr")
        service = Gul::Scan::xpath_attr(:xpath => port, :attr => "service")

        id = get_service_id(:host    => ipv4,
                            :port    => s_port,
                            :service => service,
                            :create  => true)

        port.xpath("account").each do |account|


          data = ""

          account.xpath("./*").each do |x|
            data << x.node_name + ": " + x.text + "\n"
          end

          insert_service_values(:id     => id,
                                :source => "ettercap",
                                :title  => "credentials",
                                :data   => data )


        end

      end

    end

    @db.execute("END TRANSACTION")
  end

end

class P0f < Generic

  def parse(path)
    self.p0f2sql(path)
  end

  def p0f2sql(xmlpath)

    @f = File.open(xmlpath)

    @db.execute("BEGIN TRANSACTION")

    while (line = @f.gets) != nil
      next unless line.start_with? "<"
      begin
        ip = line.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/)[0]
        os = line.match(/ - (.*?)\(/)
        if os.nil?
          os = line.match(/ - (.*?)/)
        end
        os = os[1]
      rescue
        puts line
        next
      end

      os.strip!
      next if os.length == 0 or os.start_with? "UNKNOWN"


      insert_host_values(:ip    => ip,
                         :title => "os:type",
                         :data  => os)
    end

    @db.execute("END TRANSACTION")

  end

end

class SslScan < Generic

  def xml2sql(xmlpath)

    super

    items = @xml.xpath("//document/ssltest/cipher")
    s_host = Gul::Scan::xpath_attr(:xpath => @xml.xpath("//document/ssltest"), :attr => "host")
    s_port = Gul::Scan::xpath_attr(:xpath => @xml.xpath("//document/ssltest"), :attr => "port")

    if items.nil? or items.length == 0
      puts "#{xmlpath}: No items found"
      return
    end

    if s_host.nil? or s_port.nil?
      puts "#{xmlpath}: Failed to validate host (#{s_host}) / port (#{s_port})"
      return
    end

    @db.execute("BEGIN TRANSACTION")

    id = get_service_id( :host   => s_host,
                         :port   => s_port,
                         :create => true)

    items.each do |item|

      puts item.xpath("status")

      if Gul::Scan::xpath_attr(:xpath => item, :attr => "status") == "accepted"
        insert_service_values( :id     => id,
                               :source => "sslscan",
                               :title  => "accepted-cipher",
                               :data   => "%s - %s bits - %s" % [ Gul::Scan::xpath_attr(:xpath => item, :attr => "sslversion"),
                                                                  Gul::Scan::xpath_attr(:xpath => item, :attr => "bits"),
                                                                  Gul::Scan::xpath_attr(:xpath => item, :attr => "cipher") ] )
      end
    end

    subjects = @xml.xpath("//document/ssltest/certificate/subject")
    subjects.each do |subject|

      subject.text.split('/').each do |item|
        key, value = item.split('=')
        if key == "CN" and not value.start_with? "*"
          insert_host_values(:ip    => s_host,
                             :title => "hostname:PTR",
                             :data  => value)
        end
      end

      #
      #
      #
      #
      #
      #
      #

    end

    @db.execute("END TRANSACTION")
  end

end

end

end

if $0 == __FILE__

  options = {}

  opts = OptionParser.new
  opts.banner = "Usage: #{$0} [options] <xml_files>"

  opts.on("-o", "--output OUTPUT", "The sqlite database name") do |o|
    options[:output] = o
  end

  opts.on("-t", "--type TYPE", "The xml files type (nikto|nmap|ettercap|p0f|sslscan)") do |t|
    if    t.downcase == "nmap"
      options[:type] = Gul::Scan::Nmap
    elsif t.downcase == "nikto"
      options[:type] = Gul::Scan::Nikto
    elsif t.downcase == "ettercap"
      options[:type] = Gul::Scan::Ettercap
    elsif t.downcase == "p0f"
      options[:type] = Gul::Scan::P0f
    elsif t.downcase == "burp"
      options[:type] = Gul::Scan::Burp
    elsif t.downcase == "sslscan"
      options[:type] = Gul::Scan::SslScan
    end
  end

  opts.parse!

  if options[:output].nil? and ARGV.length == 1
    options[:output] = File.basename(ARGV[0], ".xml") + ".sqlite"

  end

  if options[:output].nil? or options[:type].nil? or ARGV.length < 1
    puts opts.help
    exit
  end

  parser = options[:type].new(options[:output])

  ARGV.each do |xmlfile|
    puts "Processing #{xmlfile}"
    parser.parse(xmlfile)
  end

  parser.close

end
