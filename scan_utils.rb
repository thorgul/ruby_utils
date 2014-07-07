#!/usr/bin/env ruby

require 'nokogiri'
require 'sqlite3'
require 'optparse'


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

    @db.execute( "create table if not exists host_info (" +
                 "id integer primary key autoincrement,"  +
                 "ip varchar(15),"                        +
                 "title TEXT,"                            +
                 "data TEXT )" )
    @db.execute( "create table if not exists port_info (" +
                 "id integer primary key autoincrement,"  +
                 "ip varchar(15),"                        +
                 "port smallint,"                         +
                 "service TEXT )" )
    @db.execute( "create table if not exists service_info (" +
                 "id integer,"                               +
                 "source TEXT,"                              +
                 "title TEXT,"                               +
                 "data TEXT )" )

  end

  def insert_host_values(values=nil)
    preped = @db.prepare( "insert into host_info values(NULL, ?, ?, ?)" )
    preped.bind_params(values[:ip],
                       values[:title],
                       values[:data] )
    preped.execute!
    preped.close
  end


  def insert_port_values(values=nil)

    false if values.nil?

    preped = @db.prepare( "insert into port_info values(NULL, ?, ?, ?)" )
    preped.bind_params( values[:host],
                        values[:port],
                        values[:service] )
    preped.execute!
    preped.close
    true
  end

  def insert_service_values(values=nil)
    preped = @db.prepare( "insert into service_info values(?, ?, ?, ?)" )
    preped.bind_params( values[:id],
                        values[:source],
                        values[:title],
                        values[:data] )
    preped.execute!
    preped.close
  end


  def get_service_id(values=nil)

    return nil if values.nil?

    id = @db.get_first_value( "select id from port_info where ip = ? and port = ?",
                             values[:host],
                             values[:port])

    return id unless id.nil?
    return id if values[:create] == false

    values[:create] = false
    insert_port_values(values)

    return get_service_id(values)

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

    super

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


end

end

if $0 == __FILE__

  options = {}

  opts = OptionParser.new
  opts.banner = "Usage: #{$0} [options] <xml_files>"

  opts.on("-o", "--output OUTPUT", "The sqlite database name") do |o|
    options[:output] = o
  end

  opts.on("-t", "--type TYPE", "The xml files type (nikto|nmap)") do |t|
    if    t.downcase == "nmap"
      options[:type] = Gul::Scan::Nmap
    elsif t.downcase == "nikto"
      options[:type] = Gul::Scan::Nikto
    elsif t.downcase == "ettercap"
      options[:type] = Gul::Scan::Ettercap
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
    parser.xml2sql(xmlfile)
  end

  parser.close

end
