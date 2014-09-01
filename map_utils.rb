#!/usr/bin/env ruby

require 'sqlite3'
require 'optparse'
require 'net/smb'

require 'debug_utils'

# $debug = true

module Gul

module Map

class Generic

  def initialize(path)

    @db = SQLite3::Database.new( path )

  end

  def service_match?(id, name)
    preped = @db.prepare( "select service from port_info where id = ? and service like ?" )
    preped.bind_params( id, name )
    port_service = preped.execute!
    preped.close
    # puts "port_service => #{port_service} / #{port_service.length}"
    return true if port_service.include?(name)

    preped = @db.prepare( "select service from port_info where id = ? and service like ?" )
    preped.bind_params( id, name )
    service_title = preped.execute!
    preped.close
    # puts "port_service => #{service_title} / #{service_title.length} -- #{service_title.include? name}"
    service_title.each do |st|
      return true if st.include?(name)
    end

    false

  end

  def ssl_service?(id)

    preped = @db.prepare( "select title from service_info where id = ? and title like '%ssl%'" )
    preped.bind_params( id )
    ssl_info = preped.execute!
    preped.close

    # puts "ssl_info => #{ssl_info} / #{ssl_info.length}"
    return true if ssl_info.length >= 1

    service_match?(id, "https")

  end


  def close()

    @db.close

  end

end

class Screenshot < Generic

  def parse(opts)

    @db.execute("BEGIN TRANSACTION")

    # HTTP/HTTPS
    targets = @db.execute( "select id,ip,port from port_info where service like '%http%'" )
    targets.each do |t|
      id   = t[0]
      ip   = t[1]
      port = t[2]

      preped = @db.prepare( "select data from host_info where ip = ? and title like 'hostname:%'" )
      preped.bind_params( ip )
      hostnames = preped.execute!
      preped.close

      hostnames.flatten!
      hostnames << ip

      if ssl_service?(id)
        # puts "https://#{ip}:#{port}"
        hostnames.each do |h|
          system("/home/gul/work/tools/web/cutycapt/CutyCapt/CutyCapt --url=https://#{h}:#{port}/ --out=#{opts[:outdir]}/screenshot_https_#{h}:#{port}.png --delay=10000 --insecure")
        end
      else
        # puts "http://#{ip}:#{port}"
        hostnames.each do |h|
          system("/home/gul/work/tools/web/cutycapt/CutyCapt/CutyCapt --url=http://#{h}:#{port}/  --out=#{opts[:outdir]}/screenshot_http_#{h}:#{port}.png --delay=10000")
        end
      end

    end

    # VNC
    targets = @db.execute( "select id,ip,port from port_info where service like '%vnc%' and service not like 'vnc-http %'" )

    targets.each do |t|
      id   = t[0]
      ip   = t[1]
      port = t[2]

      system("/home/gul/work/tools/web/vncsnapshot/bin/vncsnapshot -quiet #{ip}#{port} screenshot_vnc_#{ip}:#{port}.png")
    end

    @db.execute("END TRANSACTION")


  end

end

class Smb < Generic

  def insert_service_values(values=nil)

    false if values.nil?

    preped = @db.prepare( "insert into service_info select ?, ?, ?, ? where not exists(select 1 from service_info where id = ? and source = ? and title = ? and data = ?)" )
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

  def map_netshares(opts)
    targets = @db.execute( "select id,ip from port_info where port = 445" )

    targets.each do |t|
      id   = t[0]
      ip   = t[1]

      @db.execute("BEGIN TRANSACTION")

      begin

        smbhost = SmbHost.new(:ip => ip,
                              :username => opts[:username]
                              :password => opts[:password],
                              :domain   => opts[:domain])

        shares = smbhost.list_shares()
        shares.each do |s|
          unless s.downcase == "admin$" or
                 s.downcase == "ipc$" or
                 s.downcase == "print$"
            print_info "Share found: #{ip}/#{s}"
            insert_service_values({
                                    :id     => id,
                                    :source => "netbios-map",
                                    :title  => "netbios-share",
                                    :data   => s,
                                  })
          end
        end
      rescue Exception => e
        print_debug "#{e}"
      end

      @db.execute("END TRANSACTION")

    end

  end

  def map_important_files(opts)

    targets = @db.execute( "SELECT distinct port_info.id,ip,data " +
                           "FROM port_info "          +
                           "LEFT JOIN service_info "  +
                           "ON port_info.id=service_info.id " +
                           "WHERE title LIKE '%netbios-share%'")


    if opts[:resume]
      rindex = 0
      targets.each_with_index do |entry, index|
        ip    = entry[1]
        share = entry[2]
        if opts[:resume] == "smb://#{ip}/#{share}" or opts[:resume] == "smb://#{ip}/#{share}/"
          rindex = index
          break
        end
      end
      targets = targets[rindex..-1]
    end

    targets.each do |t|

      id    = t[0]
      ip    = t[1]
      share = t[2]

      print_info "Processing smb://#{ip}/#{share}/"

      @db.execute("BEGIN TRANSACTION")

      begin
        smbhost = SmbHost.new(:ip => ip,
                              :username => opts[:username]
                              :password => opts[:password],
                              :domain   => opts[:domain])
        ifiles = smbhost.list_files("smb://#{ip}/#{share}/")
        print_info "Found #{ifiles.length} files !"

        ifiles.each do |i|
          insert_service_values({
                                  :id     => id,
                                  :source => "netbios-map",
                                  :title  => "important-files",
                                  :data   => i,
                                })
        end

      rescue Exception => e
        print_error "HONOES !!! #{e}"
      end

      @db.execute("END TRANSACTION")

    end

  end

  def parse(opts)

    unless opts[:resume]
      map_netshares(opts)
    end
    map_important_files(opts)

  end

end

class SmbHost

  @@IMPORTANT_REGEX_NAME= [
                           /password.*?(doc|xls|txt|old|backup|bak|log|conf)/i,
                           /\.kdbx?$/i,
                           /\.config$/i
                          ]

  @@IMPORTANT_REGEX_PATH = [
                            /(Documents and Settings|Users)\/.*?\/Desktop\//i,
                            /(Documents and Settings\/.*?\/Application Data|Users\/.*?\/AppData\/Roaming)\/Mozilla\/Firefox\/Profiles\/(key3.db|signons.sqlite|bookmarks.html|places.sqlite|cookies.sqlite)/i,
                            /Windows\/NTDS\/ntds.dit/i,
                            /eftops.*\/.*?debug.*?\.(log|zip|bak|backup|xml|conf)/i
                           ]

  # :ip
  # :username
  # :password
  # :domain
  def initialize(opts)
    @ip = opts[:ip]
    @conn = Net::SMB.new

    @username = opts[:username]
    @password = opts[:password]
    @domain   = opts[:domain]

    @conn.auth_callback {|server, share|
      [@username, @password]
    }

  end

  def important?(obj)

    @@IMPORTANT_REGEX_NAME.each do |r|
      return true unless obj.name.to_s.match(r).nil?
    end

    url = obj.url.to_s
    if obj.dir?
      url += "/"
    end

    @@IMPORTANT_REGEX_PATH.each do |r|
      return true unless url.match(r).nil?
    end

    false
  end

  def list_files(path)

    files = []

    smbdir = @conn.opendir(path)

    while dent = smbdir.read
      next if dent.name.to_s == "." or dent.name.to_s == ".."

      if important?(dent)
        print_debug "Found: " + path + dent.name.to_s
        files << path + dent.name.to_s
      end

      if dent.file?
        # puts "File: " + path + dent.name.to_s
      elsif dent.dir? and not dent.link?
        # puts "Dir:  " + path + dent.name.to_s
        begin
          files = files + list_files(path + dent.name.to_s + "/")
        rescue Exception => e
          print_debug "#{e}"
        end
      end
    end

    begin
      smbdir.close
    rescue Exception => e
      print_debug "#{e}"
    end

    files

  end

  def list_shares()
    shares = []

    begin
      @conn.opendir("smb://#{@ip}/") do |smbdir|
        while dent = smbdir.read
          shares << dent.name
        end
      end
    rescue Exception => e
      print_debug "#{e}"
    end

    shares
  end


end

end

end

if $0 == __FILE__

  options = {
    :actions => [],
    :output  => "./"
  }

  opts = OptionParser.new
  opts.banner = "Usage: #{$0} [options] <xml_files>"

  opts.on("-o", "--output OUTPUT", "The output directory") do |o|
    options[:output] = o
  end

  opts.on("-r", "--resume URL", "Where you want to resume the mapping from") do |url|
    options[:resume] = url
  end

  opts.on("-U", "--username USERNAME") do |username|
    options[:username] = username
  end

  opts.on("-P", "--password PASSWORD") do |password|
    options[:password] = password
  end

  opts.on("-D", "--domain DOMAIN")     do |domain|
    options[:domain]   = domain
  end


  opts.on("-a", "--action ACTION", "The action you want to perform (default: all)") do |a|
    case a.downcase
    when "screenshot"
      options[:actions] << Gul::Map::Screenshot
    when "smb"
      options[:actions] << Gul::Map::Samba
    end
  end

  opts.on("-d", "--debug") do
    $debug = true
  end

  opts.parse!

  if options[:actions].length == 0
    # options[:actions] << Gul::Map::Screenshot
    options[:actions] << Gul::Map::Smb
  end


  ARGV.each do |sqlfile|
    puts "Processing #{sqlfile}"
    options[:actions].each do |a|
      action = a.new(sqlfile)
      action.parse(options) # options[:output])
      action.close()
    end
  end


end
