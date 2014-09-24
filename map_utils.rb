#!/usr/bin/env ruby

require 'sqlite3'
require 'optparse'
require 'net/smb'
require 'digest'
require 'debug_utils'

# $debug = true

module Gul

module Map

class Generic

  def initialize(path)

    @db = SQLite3::Database.new( path )
    @prep = {
      :service_match        => @db.prepare( "SELECT service " +
                                            "FROM port_info " +
                                            "WHERE id = ? "   +
                                            "AND service like ?" ),
      :insert_port_values   => @db.prepare( "INSERT INTO port_info " +
                                            "SELECT NULL, ?, ?, ? "  +
                                            "WHERE NOT EXISTS( "     +
                                            "                 SELECT 1 " +
                                            "                 FROM port_info " +
                                            "                 WHERE ip = ? "   +
                                            "                 AND port = ? "   +
                                            "                 AND service = ?)" ),
      :insert_service_value => @db.prepare( "INSERT INTO service_info " +
                                            "SELECT ?, ?, ?, ? "        +
                                            "WHERE NOT EXISTS("         +
                                            "                 SELECT 1 " +
                                            "                 FROM service_info " +
                                            "                 WHERE id = ? "      +
                                            "                 AND source = ? "    +
                                            "                 AND title = ? "     +
                                            "                 AND data = ?)" ),
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

  def insert_port_values(values=nil)

    false if values.nil?

    @prep[:insert_port_values].execute!( values[:host],
                                         values[:port],
                                         values[:service],
                                         values[:host],
                                         values[:port],
                                         values[:service] )
    true
  end

  def insert_service_values(values=nil)

    false if values.nil?

    @prep[:insert_service_value].execute!( values[:id],
                                           values[:source],
                                           values[:title],
                                           values[:data],
                                           values[:id],
                                           values[:source],
                                           values[:title],
                                           values[:data] )
    true
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

end

class Screenshot < Generic

  def parse(opts)

    @db.execute("BEGIN TRANSACTION")

    # HTTP/HTTPS
    targets = @prep[:get_http_services].execute!
    targets.each do |t|
      id   = t[0]
      ip   = t[1]
      port = t[2]

      hostnames = @prep[:get_ip_hostnames].execute!(ip).flatten!
      (hostnames.nil? && hostnames = [ ip ]) || hostnames << ip

      if ssl_service?(id)
        # puts "https://#{ip}:#{port}"
        hostnames.each do |h|
          output = "#{opts[:output]}/screenshot_https_#{h}:#{port}.png"
          if opts[:resume].nil? or ( File.exist?(output) and Digest::MD5.hexdigest(File.read(output)) == "5d3a8ed3031d0c01bfeb20ef4f19dc92" )
            print_debug "#{h}:#{port}"
            system("CutyCapt --url=https://#{h}:#{port}/ --out=#{output} --delay=10000 --insecure")
          end
          insert_service_values(:id     => get_service_id(:host => ip, :port => port),
                                :source => "map_utils",
                                :title  => "screenshot",
                                :data   => output)

        end
      else
        # puts "http://#{ip}:#{port}"
        hostnames.each do |h|
          output = "#{opts[:output]}/screenshot_http_#{h}:#{port}.png"
          if opts[:resume].nil? or ( File.exist?(output) and Digest::MD5.hexdigest(File.read(output)) == "5d3a8ed3031d0c01bfeb20ef4f19dc92" )
            print_debug "#{h}:#{port}"
            system("CutyCapt --url=http://#{h}:#{port}/  --out=#{output} --delay=10000")
          end
          insert_service_values(:id     => get_service_id(:host => ip, :port => port),
                                :source => "map_utils",
                                :title  => "screenshot",
                                :data   => output)

        end
      end

    end

    # VNC
    targets = @prep[:get_vnc_services].execute!
    targets.each do |t|
      id   = t[0]
      ip   = t[1]
      port = t[2]

      system("/home/gul/work/tools/web/vncsnapshot/bin/vncsnapshot -quiet #{ip}:#{port} screenshot_vnc_#{ip}:#{port}.png")
    end

    @db.execute("END TRANSACTION")


  end

end

class Smb < Generic

  def map_netshares(opts)

    if opts[:targets].nil?
      targets = @prep[:get_smb_services].execute!
    else
      targets = opts[:targets].map do |ip|
        id = get_service_id(:host => ip, :port => 445, :create => false)
        (id.nil? && nil) || [ id, ip ]
      end
    end


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
      id   = t[0]
      ip   = t[1]

      @db.execute("BEGIN TRANSACTION")

      begin

        smbhost = SmbHost.new(:ip => ip,
                              :username  => opts[:username],
                              :password  => opts[:password],
                              :workgroup => opts[:workgroup])

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

  def map_files(opts)

    if opts[:targets].nil?
      targets = @prep[:get_smb_shares].execute!
    else
      targets = opts[:targets].map do |t|
        ip, share = t.split("/")
        id = get_service_id(:host => ip, :port => 445, :create => false)
        (id.nil? && nil) || [ id, ip, share ]
      end
    end

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
                              :username  => opts[:username],
                              :password  => opts[:password],
                              :workgroup => opts[:workgroup])
        ### ifiles = smbhost.list_files("smb://#{ip}/#{share}/")
        ### print_info "Found #{ifiles.length} files !"

        smbhost.get_users_home_dir("smb://#{ip}/#{share}/").each do |home|
          smbhost.get_credentials(home, true)
        end
        # smbhost.list_files("smb://#{ip}/#{share}/")

        ### ifiles.each do |i|
        ###   insert_service_values({
        ###                           :id     => id,
        ###                           :source => "netbios-map",
        ###                           :title  => "netbios-shared-file",
        ###                           :data   => i,
        ###                         })
        ### end
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
    map_files(opts)

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

    @username  = opts[:username]
    @password  = opts[:password]
    @workgroup = opts[:workgroup]

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

      # if important?(dent)
        print_debug "Found: " + path + dent.name.to_s
        files << path + dent.name.to_s
      # end

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

  def get_users_home_dir(path)

    home_dir = []
    user_dir = nil
    share = @conn.opendir(path)

    while dent = share.read
      if dent.name.to_s == "Documents and Settings" or
          dent.name.to_s == "Users"
        user_dir = dent.name.to_s
        break
      end
    end

    return if user_dir.nil?

    while dent = @conn.opendir(user_dir).read
      next if dent.name.to_s == "." or dent.name.to_s == ".."
      home_dir << dent.name.to_s
      print_debug "Found: " + path + dent.name.to_s
    end

    home_dir

  end

  def get_credentials(path, path_is_home_dir=false)

    credz = []

    return if path_is_home_dir == false

    appdata = nil
    if    path.includes? "Documents and Settings"
      appdata = "#{path}/Application Data"
    elsif path.includes? "Users"
      appdata = "#{path}/AppData/Roaming"
    end
    return if appdata.nil?

    # Firefox !
    while dent = @conn.opendir("#{appdata}/Mozilla/Firefox/Profiles").read
      next if dent.name.to_s == "." or dent.name.to_s == ".."

      while profile = @conn.opendir("#{dent.name.to_s}").read
      # key3.db|signons.sqlite|bookmarks.html|places.sqlite|cookies.sqlite
        if  dent.name.to_s == "key3.db" or
            dent.name.to_s == "signons.sqlite"
          print_debug "Found: " + path + dent.name.to_s
          credz << dent.name.to_s
        end
      end
    end

    credz
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
  opts.banner = "Usage: #{$0} [options] sqlite_file1 <sqlite_file2> <sqlite_file3> ..."

  opts.on("-o", "--output OUTPUT", "The output directory") do |o|
    options[:output] = o
  end

  opts.on("-r", "--resume URL", "Where you want to resume the mapping from") do |url|
    options[:resume]   = url
  end

  opts.on("-t", "--targets URL", "A comma spearated list of targets. that's if you don't want to pull from the database") do |urls|
    options[:targets] = urls.split(",")
  end

  opts.on("-U", "--username USERNAME") do |username|
    options[:username] = username
  end

  opts.on("-P", "--password PASSWORD") do |password|
    options[:password] = password
  end

  opts.on("-W", "--workgroup WORKGROUP")     do |domain|
    options[:workgroup]   = domain
  end


  opts.on("-a", "--action ACTION", "The action you want to perform (default: all)") do |a|
    case a.downcase
    when "screenshot"
      options[:actions] << Gul::Map::Screenshot
    when "smb"
      options[:actions] << Gul::Map::Smb
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

  if options[:actions].length == 0
    # options[:actions] << Gul::Map::Screenshot
    options[:actions] << Gul::Map::Smb
  end


  ARGV.each do |sqlfile|
    puts "Processing #{sqlfile}"
    options[:actions].each do |a|
      action = a.new(sqlfile)
      action.parse(options) # options[:output])
    end
  end


end
