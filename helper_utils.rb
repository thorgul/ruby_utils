#!/usr/bin/env ruby

require 'sqlite3'
require 'optparse'
require 'net/smb'
require 'digest'
require 'debug_utils'

# $debug = true

module Gul

module Helper

class Generic

  def initialize(path)

    @db = SQLite3::Database.new( path )
    @prep = {
      :service_match        => @db.prepare( "SELECT service " +
                                            "FROM port_info " +
                                            "WHERE id = ? "   +
                                            "AND service like ?" ),
      :get_service_id       => @db.prepare( "SELECT id "      +
                                            "FROM port_info " +
                                            "WHERE ip = ? "   +
                                            "AND port = ?" ),
      :ssl_service          => @db.prepare( "SELECT title "      +
                                            "FROM service_info " +
                                            "WHERE id = ? "      +
                                            "AND title LIKE '%ssl%'" ),
      :get_http_services    => @db.prepare( "SELECT id,ip,port " +
                                            "FROM port_info "    +
                                            "WHERE service LIKE '%http%'" ),
      :get_ssl_services     => @db.prepare( "SELECT DISTINCT port_info.id,ip,port " +
                                            "FROM port_info "                       +
                                            "LEFT JOIN service_info "               +
                                            "ON port_info.id=service_info.id "      +
                                            "WHERE service_info.title LIKE '%ssl%'" ),
      :get_ip_hostnames     => @db.prepare( "SELECT data "    +
                                            "FROM host_info " +
                                            "WHERE ip = ? "   +
                                            "AND title LIKE 'hostname:%'" ),
      :get_vnc_services     => @db.prepare( "SELECT id,ip,port "          +
                                            "FROM port_info "             +
                                            "WHERE service LIKE '%vnc%' " +
                                            "AND service NOT LIKE 'vnc-http %'" ),
      :get_smb_services     => @db.prepare( "SELECT id,ip "   +
                                            "FROM port_info " +
                                            "WHERE port = 445" ),
      :get_smb_shares       => @db.prepare( "SELECT DISTINCT port_info.id,ip,data " +
                                            "FROM port_info "                       +
                                            "LEFT JOIN service_info "               +
                                            "ON port_info.id=service_info.id "      +
                                            "WHERE title LIKE '%netbios-share%'" )
    }
    @db.execute("PRAGMA synchronous   = OFF")
    @db.execute("PRAGMA journal_mode  = MEMORY")
    @db.execute("PRAGMA cache_size    = 50000")
    @db.execute("PRAGMA count_changes = OFF")
  end

  def service_match?(id, name)
    service_title = @prep[:service_match].execute!( id, name )

    service_title.each do |st|
      return true if st.include?(name)
    end

    false
  end

  def get_service_id(values=nil)

    return nil if values.nil?

    id = @prep[:get_service_id].execute!( values[:host],
                                          values[:port] ).flatten[0]

    return id unless id.nil?
    return id if values[:create] == false

    values[:create] = false
    insert_port_values(values)

    return get_service_id(values)

  end

  def ssl_service?(id)

    ssl_info = @prep[:ssl_service].execute!( id )

    # puts "ssl_info => #{ssl_info} / #{ssl_info.length}"
    return true if ssl_info.length >= 1

    service_match?(id, "https")

  end

end # Gul::Helper::Generic

class Nikto < Generic

  def parse(opts)

    @db.execute("BEGIN TRANSACTION")

    # HTTP/HTTPS
    @prep[:get_http_services].execute!.each do |t|

      id   = t[0]
      ip   = t[1]
      port = t[2]

      hostnames = @prep[:get_ip_hostnames].execute!(ip).flatten!
      (hostnames.nil? && hostnames = [ ip ]) || hostnames << ip

      hostnames.each do |h|
        print_debug "#{h}:#{port}"
        cmd = "nikto -Format xml -o #{opts[:output]}nikto_#{h}:#{port}.xml -host #{h} -port #{port}"
        cmd << " -ssl" if ssl_service?(id)
        print_info cmd
      end

    end

    @db.execute("END TRANSACTION")

  end

end

class SslScan < Generic

  def parse(opts)

    @db.execute("BEGIN TRANSACTION")

    # SSL
    @prep[:get_ssl_services].execute!.each do |t|

      id   = t[0]
      ip   = t[1]
      port = t[2]

      print_debug "#{ip}:#{port}"
      cmd = "sslscan --xml=#{opts[:output]}sslscan_#{ip}:#{port}.xml #{ip}:#{port}"
      print_info cmd

    end

    @db.execute("END TRANSACTION")

  end

end # Gul::Helper::Nikto

end # Gul::Helper

end # Gul

if $0 == __FILE__

  options = {
    :actions => [],
    :output  => "./"
  }

  opts = OptionParser.new
  opts.banner = "Usage: #{$0} [options] sqlite_file1 <sqlite_file2> <sqlite_file3> ..."

  opts.on("-o", "--output OUTPUT", "The output directory") do |o|
    options[:output] = o
    options[:output] << "/" unless options[:output].end_with? "/"
  end

  opts.on("-a", "--action ACTION", "The action you want to perform (default: all)") do |a|
    case a.downcase
    when "nikto"
      options[:actions] << Gul::Helper::Nikto
    when "sslscan"
      options[:actions] << Gul::Helper::SslScan
    else
      print_error "Unknown action #{a}"
      puts opts.banner
      exit
    end
  end

  opts.on("-d", "--debug") do
    $debug = true
  end

  opts.parse!

  ARGV.each do |sqlfile|
    puts "Processing #{sqlfile}"
    options[:actions].each do |a|
      action = a.new(sqlfile)
      action.parse(options) # options[:output])
    end
  end


end
