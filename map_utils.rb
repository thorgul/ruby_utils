#!/usr/bin/env ruby

require 'sqlite3'
require 'optparse'
require 'digest'
require 'debug_utils'

begin
  require 'net/smb'
rescue LoadError => e
  print_error e.to_s
  print_error "SMB mapping functions won't work without net/smb !"
end

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
      :get_http_services    => @db.prepare( "SELECT DISTINCT id,ip,port " +
                                            "FROM port_info "    +
                                            "WHERE service LIKE '%http%'" ),
      :get_ip_hostnames     => @db.prepare( "SELECT DISTINCT data "    +
                                            "FROM host_info " +
                                            "WHERE ip = ? "   +
                                            "AND title LIKE 'hostname:%'" ),
      :get_vnc_services     => @db.prepare( "SELECT DISTINCT id,ip,port "          +
                                            "FROM port_info "             +
                                            "WHERE service LIKE '%vnc%' " +
                                            "AND service NOT LIKE 'vnc-http %'" ),
      :get_smb_services     => @db.prepare( "SELECT DISTINCT id,ip "   +
                                            "FROM port_info " +
                                            "WHERE port = 445" ),
      :get_smb_shares       => @db.prepare( "SELECT DISTINCT port_info.id,ip,data " +
                                            "FROM port_info "                       +
                                            "LEFT JOIN service_info "               +
                                            "ON port_info.id=service_info.id "      +
                                            "WHERE title LIKE '%netbios-share%'" ),
      :get_target_smb_shares => @db.prepare( "SELECT DISTINCT port_info.id,ip,data " +
                                             "FROM port_info "                       +
                                             "LEFT JOIN service_info "               +
                                             "ON port_info.id=service_info.id "      +
                                             "WHERE title LIKE '%netbios-share%' AND " +
                                             "port_info.ip = ?")
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

      proto = "http"
      proto << "s" if ssl_service?(id)

      # puts "https://#{ip}:#{port}"
      hostnames.each do |h|
        output = "#{opts[:output]}/screenshot_#{proto}_#{h}:#{port}.png"

        if opts[:resume].nil? or ( File.exist?(output) and Digest::MD5.hexdigest(File.read(output)) == "5d3a8ed3031d0c01bfeb20ef4f19dc92" )
          print_debug "#{h}:#{port} (#{output})"
          command =  "CutyCapt --url=#{proto}://#{h}:#{port}/ --out=#{output} --delay=10000"
          command << " --insecure"      if proto  == "https"
          command << " 2>&1 >/dev/null" if $debug == false
          system(command)
        end

        insert_service_values(:id     => get_service_id(:host => ip, :port => port),
                              :source => "map_utils",
                              :title  => "screenshot",
                              :data   => output)
      end

    end

    # VNC
    targets = @prep[:get_vnc_services].execute!
    targets.each do |t|
      id   = t[0]
      ip   = t[1]
      port = t[2]

      output = "#{opts[:output]}/screenshot_vnc_#{ip}:#{port}.png"
      system("/home/gul/work/tools/web/vncsnapshot/bin/vncsnapshot -quiet #{ip}:#{port} #{output}")

      insert_service_values(:id     => get_service_id(:host => ip, :port => port),
                            :source => "map_utils",
                            :title  => "screenshot",
                            :data   => output)

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
        # id = get_service_id(:host => ip, :port => 445, :create => false)
        id = get_service_id(:host => ip, :port => 445, :create => true)
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
        unless shares.nil?

          shares.each do |s|
            unless s.downcase == "admin$" or
                s.downcase == "ipc$" or
                s.downcase == "print$"
              # print_info "Share found: - #{id} - #{ip}/#{s}"
              print_info "Share found: - #{ip}/#{s}"
              insert_service_values({
                                      :id     => id,
                                      :source => "netbios-map",
                                      :title  => "netbios-share",
                                      :data   => s,
                                    })
            end
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
      targets = []
      opts[:targets].each do |t|
        if t.include? "/"
          s = t.split("/")
          ip = s[0]
          share = s[1..-1].join("/")
          id = get_service_id(:host => ip, :port => 445, :create => false)
          targets << (id.nil? && nil) || [ id, ip, share ]
        else
          targets += @prep[:get_target_smb_shares].execute!(t)
        end
      end
    end

    print_debug targets

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

        unless not opts[:credzonly].nil? and opts[:credzonly] == true
          ifiles = smbhost.list_files("smb://#{ip}/#{share}/")
          # puts "#{ifiles.length}"
        end

        if share.downcase == "users" or
           share.downcase == "documents and settings"
          users_home = smbhost.get_users_home_dir("smb://#{ip}/")
        else
          users_home = smbhost.get_users_home_dir("smb://#{ip}/#{share}/")
        end

        unless users_home.nil?

          users_home.each do |home|
            smbhost.get_credentials(home, true)
            smbhost.list_files("#{home}/Desktop/")
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
        end
      rescue Exception => e
        print_error "HONOES !!! #{e}"
      end

      @db.execute("END TRANSACTION")

    end

  end

  def parse(opts)

    # print_error "!!! map_netshare is deactivated !!!"
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
                            /(Documents and Settings\/.*?\/Application Data|Users\/.*?\/AppData\/Roaming)\/Mozilla\/Firefox\/Profiles\/(cert8.db|key3.db|signons.sqlite|bookmarks.html|places.sqlite|cookies.sqlite)/i,
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

    # print_debug "#{@workgroup}\\#{@username}%#{@password}"
    @conn.auth_callback {|server, share|
      [@username, @password, @workgroup]
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

    begin

      smbdir = @conn.opendir(path)

      while dent = smbdir.read
        next if dent.name.to_s == "." or dent.name.to_s == ".."

        # if important?(dent)
        print_info "Found: " + path + dent.name.to_s
        files << path + dent.name.to_s
        # end

        # if dent.file?
        # puts "File: " + path + dent.name.to_s
        # elsif dent.dir? and not dent.link?
        if dent.dir? and not dent.link?
          files = files + list_files(path + dent.name.to_s + "/")
        end
      end

      smbdir.close

    rescue Exception => e
      print_debug "#{e}"
    end

    files

  end

  def list_shares()
    shares = []

    print_debug "smb://#{@ip}/"
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
    user_dir = []
    print_debug "$HOME: #{path}"
    share = @conn.opendir(path)

    while dent = share.read
      if  dent.name.to_s == "Users" or
          dent.name.to_s == "Documents and Settings"
        user_dir = dent.name.to_s

        print_debug "User dir => #{user_dir}"

        begin

          @conn.opendir("#{path}/#{user_dir}") do |user_dir_path|

            while dent = user_dir_path.read
              next if dent.name.to_s == "." or dent.name.to_s == ".."
              home_dir << "#{path}/#{user_dir}/#{dent.name}"
              print_debug "Found: " + "#{path}/#{user_dir}/#{dent.name}"
            end

          end

        rescue Exception => e
          print_debug "#{e}"
        end

      end
    end

    # return if user_dir.nil?

    home_dir

  end

  def get_credentials(path, path_is_home_dir=false)

    credz = []

    return if path_is_home_dir == false

    ### # DEBUG !!!
    ### begin
    ###   profiles = @conn.opendir("#{appdata}")
    ###   while dent = profiles.read
    ###     print_debug "#{appdata}/#{dent.name}"
    ###   end
    ### rescue => e
    ###   print_debug "#{e}"
    ### end

    # Firefox !
    begin
      print_debug "#{path}"
      appdata = nil
      if    path.to_s.include? "Documents and Settings"
        appdata = "#{path}/Application Data"
      elsif path.to_s.include? "Users"
        appdata = "#{path}/AppData/Roaming"
      end
      raise if appdata.nil?

      profiles = @conn.opendir("#{appdata}/Mozilla/Firefox/Profiles")
      while dent = profiles.read
        next if dent.name.to_s == "." or dent.name.to_s == ".."

        profile = @conn.opendir("#{appdata}/Mozilla/Firefox/Profiles/#{dent.name}")
        while ddent = profile.read
          if [ "key3.db",
               "signons.sqlite",
               "logins.json",
               "bookmarks.html",
               "places.sqlite",
               "cookies.sqlite",
               "cert8.db" ].include? ddent.name.to_s
          # if  ddent.name.to_s == "key3.db" or
          #     ddent.name.to_s == "signons.sqlite"
            credz << "#{appdata}/Mozilla/Firefox/Profiles/#{dent.name}/#{ddent.name}"
            print_info "Found: #{appdata}/Mozilla/Firefox/Profiles/#{dent.name}/#{ddent.name}"
          end
        end
      end
    rescue
    end

    # Chrome
    begin

      if path.to_s.include? "Documents and Settings"
        appdata = "#{path}/Local Settings/Application Data"
      elsif path.to_s.include? "Users"
        appdata = "#{path}/AppData/Local"
      end
      raise if appdata.nil?

      profiles = @conn.opendir("#{appdata}/Google/Chrome/User Data/Default")
      while dent = profiles.read
        next if dent.name.to_s == "." or dent.name.to_s == ".."

        if  dent.name.to_s == "Web Data" or
            dent.name.to_s == "Login Data"
          credz << "#{appdata}/Google/Chrome/User Data/Default/#{dent.name}"
          print_info "Found: #{appdata}/Google/Chrome/User Data/Default/#{dent.name}"
        end
      end

    rescue
    end

    # WinSCP
    begin

      if path.to_s.include? "Documents and Settings"
        appdata = "#{path}/Local Settings/Application Data"
      elsif path.to_s.include? "Users"
        appdata = "#{path}/AppData/Roaming"
      end
      raise if appdata.nil?

      profile = @conn.opendir("#{appdata}")
      while dent = profile.read
        next unless dent.name.to_s == "WinSCP.ini"

        credz << "#{appdata}/#{dent.name}"
        print_info "Found: #{appdata}/#{dent.name}"

      end

    rescue
    end

    # FileZilla
    begin

      if path.to_s.include? "Documents and Settings"
        appdata = "#{path}/Local Settings/Application Data"
      elsif path.to_s.include? "Users"
        appdata = "#{path}/AppData/Roaming"
      end
      raise if appdata.nil?


      profile = @conn.opendir("#{appdata}")
      while dent = profile.read
        next unless dent.name.to_s == "sitemanager.xml" or
                    dent.name.to_s == "filezilla.xml"

        credz << "#{appdata}/#{dent.name}"
        print_info "Found: #{appdata}/#{dent.name}"

      end

    rescue
    end

    begin

      # Program Files\FileZilla Server
      if path.to_s.include? "Program Files" or path.to_s.include? "Program Files (x86)"
        appdata = "#{path}/FileZilla Server"

        credz << "#{appdata}/FileZilla\ Server.xml"
      end

    rescue
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

  opts.on("--credz-and-desk-files-only", "Useful if you want to only get the credz and Desktop files out of a SMB share. Will be way faster") do
    options[:credzonly] = true
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
    # print_debug "Username  #{options[:username]}"
    # print_debug "Password  #{options[:password]}"
    # print_debug "Workgroup #{options[:workgroup]}"
  end

  opts.parse!

  if options[:actions].length == 0
    options[:actions] << Gul::Map::Screenshot
    options[:actions] << Gul::Map::Smb
    print_warn "no action defined. Setting SMB scan and screenshot actions"
  end

  if options[:actions].include? Gul::Map::Smb and not options[:credzonly] == true
    print_info "ARE YOU SURE YOU DO NOT WANT TO USE THE --credz-and-desk-files-only option ?"
    print_info "It will take ages, you got 5 sec to cancel !"
    5.times { print "." ; sleep 1}
    puts
  end

  ARGV.each do |sqlfile|
    puts "Processing #{sqlfile}"
    options[:actions].each do |a|
      action = a.new(sqlfile)
      action.parse(options) # options[:output])
    end
  end


end
