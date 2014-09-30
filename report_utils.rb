#!/usr/bin/env ruby

require 'optparse'
require 'sqlite3'
require 'uri'
require 'cgi'

$debug = false

class String
  def url?()
    res = self =~ /\A#{URI::regexp(['http', 'https'])}\z/
    res == nil ? false : true
  end

  def to_html()
    str = self.strip
    # str.gsub!(/\r?\n/, "<br>\n")
    if str.url? or File.exists?(str)
      str = "<a href='#{str}'>#{str}</a>"
    else
      str = str.each_line.map {|x| CGI.escapeHTML(x.strip) + "<br>" }.join
    end
    str
  end

end

module Gul

module HTML

# #boxtitle a {float:left; margin: 3px 10px 5px 5px;}
  SQLITE_REPORT_HEADER  = "
<head><title>SQLite report</title></head>
<body>
<style>
#boxtitle {border: 1px solid #CC00FF; background-color:#44aaff; padding:5px; margin-top:5px; font-size:14px; text-align: center ;}
#boxtitle a {float:left; margin: 0px 5px 0px 5px ;}
.boxbody {border: 1px solid #333333; background-color:#ffffff; padding:5px; display:block; font-size:10px}
</style>

<script language=\"javascript\">
function hideshow(id){
   if(document.getElementById(id)){
       var ele = document.getElementById(id);
       if(ele.style.display==\"none\"){
           ele.style.display=\"block\";
       }else{
           ele.style.display=\"none\";
       }
   }
}
</script>"
  SQLITE_REPORT_TRAILER = "</body>"

  def self.gen_pict_gallery(db, report)
    res = db.execute( "SELECT data FROM service_info WHERE title = 'screenshot' " )

    return if res.nil? or res.length == 0


    report.write("<div id=\"boxtitle\" onclick=\"javascript:hideshow('Screenshots');\" style=\"background-color:#ffaa44\">")
    report.write("<b>Screenshots</b>")
    report.write("</div>\n")

    report.write("<div class=\"boxbody\" id=\"Screenshots\">\n")

    res.each do |unit|
      report.write "<a href=\"#{unit[0]}\">\n"
      report.write "<img src=\"#{unit[0]}\" width=400 height=400 border=2 />\n"
      report.write "</a>\n"
    end
    report.write("</div>\n")
  end

  def self.sqlite_report_service(db, report, sqlquery, name=nil)
    res = db.execute( sqlquery )

    return if res.nil? or res.length == 0

    report.write("<div id=\"boxtitle\" onclick=\"javascript:hideshow('#{name} Servers Table');\" style=\"background-color:#ffaa44\">")
    report.write("<b>#{name} Servers</b>")
    report.write("</div>\n")

    report.write("<div class=\"boxbody\" id=\"#{name} Servers Table\">\n")

    report.write("        <table width=\"100%\">
                <tr>
                        <td style=\"width:150px\" valign=\"top\" ><b>IP</b></td>
                        <td style=\"width:150px\" valign=\"top\" ><b>Port</b></td>
                        <td><b>Service</b></td>
                </tr>
        </table>\n")

    res.each do |unit|
        report.write("        <table width=\"100%\">
                <tr>
                        <td style=\"width:150px\" valign=\"top\" ><a href=\"#services_#{unit[0]}\">#{unit[0]}</a></td>
                        <td style=\"width:150px\" valign=\"top\" >#{unit[1]}.to_html</td>
                        <td>#{unit[2].to_html}</td>
                </tr>
        </table>\n")
      end
      report.write("</div>\n")
  end

  def self.sqlite_report(opts)
    files = opts[:files]
    files = [ opts[:files] ] if files.class == String

    if File.exists?(opts[:output]) and not opts[:force] == true
      puts "#{opts[:output]} exists, no override. Use -f / --force to overwrite"
      return
    end

    report = File.open(opts[:output], "w")

    report.write(SQLITE_REPORT_HEADER)

    files.each do |file|

      unless File.exists?(file)
        puts "#{file} does not exists, skipping"
        next
      end

      db = SQLite3::Database.new( file )

      # Stupid image gallery
      gen_pict_gallery(db, report)

      # Important Web Servers
      sqlite_report_service(db, report, "SELECT DISTINCT ip, port, service " +
                                        "FROM port_info "                    +
                                        "LEFT JOIN service_info  "           +
                                        "ON port_info.id=service_info.id "   +
                                        "WHERE ( port_info.port = 80 OR port_info.port = 443 ) AND " +
                                        "      ( port_info.service  LIKE '%Lotus%' OR " +
                                        "        service_info.title LIKE '%Lotus%' OR " +
                                        "        service_info.data  LIKE '%Lotus%' ) " +
                                        "ORDER BY service",
                                        "Interesting Web Servers")

      # Databases
      sqlite_report_service(db, report, "SELECT DISTINCT ip, port, service "                         +
                                        "FROM      port_info "                                          +
                                        "LEFT JOIN service_info "                                       +
                                        "ON        port_info.id=service_info.id "                       +
                                        "WHERE (( service_info.title   NOT LIKE 'http%' AND           " +
                                        "         service_info.title   NOT LIKE 'https%'    )     OR  " +
                                        "        service_info.title IS NULL )                    AND  " +
                                        "      ( port_info.service        LIKE '%sql%'             OR " +
                                        "        service_info.title       LIKE '%sql%'             OR " +
                                        "        ( port_info.service      LIKE '%access%'       AND "   +
                                        "          port_info.service  NOT LIKE '%citrix access%' ) OR " +
                                        "        ( service_info.title     LIKE '%access%'       AND "   +
                                        "          service_info.title NOT LIKE '%citrix access%' ) OR " +
                                        "        port_info.service        LIKE '%db2%'             OR " +
                                        "        service_info.title       LIKE '%db2%' ) "              +
                                        "ORDER BY service", "Databases" )

      # Tomcat Servers
      sqlite_report_service(db, report, "SELECT DISTINCT ip, port, data "          +
                                        "FROM port_info "                          +
                                        "JOIN service_info "        +
                                        "ON port_info.id=service_info.id "         +
                                        "WHERE service LIKE '%TOMCAT%' AND "       +
                                        "      service_info.title = 'http-title' " +
                                        "ORDER BY data", "Tomcat")

      # JBoss Servers
      sqlite_report_service(db, report, "SELECT DISTINCT ip, port, data "          +
                                        "FROM port_info "                          +
                                        "JOIN service_info "        +
                                        "ON port_info.id=service_info.id "         +
                                        "WHERE service LIKE '%JBOSS%' AND "        +
                                        "      service_info.title = 'http-title' " +
                                        "ORDER BY data", "Tomcat")

      # VNC
      sqlite_report_service(db, report, "SELECT DISTINCT ip, port, data "           +
                                        "FROM port_info "                           +
                                        "JOIN service_info "                        +
                                        "ON port_info.id=service_info.id "          +
                                        "WHERE service LIKE '%VNC%' AND "           +
                                        "      service_info.title != 'http-title' " +
                                        "ORDER BY data, ip, port", "VNC")


      # Report for each server
      ips = db.execute( "select distinct ip from port_info" )
      ips.sort_by! {|ip| ip[0].to_s.split('.').map{ |octet| octet.to_i} }
      ips.each do |ip|

        if opts[:filter]
          next if opts[:filter].call(ip[0]) == false
        end

#        report.write("<div id=\"boxtitle\"><a href=\"javascript:hideshow('services_#{ip[0]}');\" id=\"title_#{ip[0]}\">+</a>#{ip[0]}</div>")
        report.write("<div id=\"boxtitle\" onclick=\"javascript:hideshow('services_#{ip[0]}');\">")
        report.write(ip[0])

        ostype = db.execute( "select distinct data from host_info where ip = ? and title like 'os:type' ", ip[0] )
        ostype.each do |type|
          report.write("<br>( " + type[0] + " )")
        end

        hostnames = db.execute( "select distinct data from host_info where ip = ? and title like 'hostname:%' ", ip[0] )
        hostnames.sort_by! {|n| n.to_s.split('.').map{ |chunk| chunk.to_s}}
        hostnames.each do |hostname|
          report.write("<br>" + hostname[0])
        end

        report.write("</div>\n")

        report.write("<div class=\"boxbody\" id=\"services_#{ip[0]}\">\n")

        ### screenshots = db.execute( "SELECT DISTINCT data "            +
        ###                           "FROM service_info "               +
        ###                           "JOIN port_info "                  +
        ###                           "ON port_info.id=service_info.id " +
        ###                           "WHERE ip = ? AND "                +
        ###                           "title = 'screenshot' ", ip[0] )
        ###
        ### unless screenshots.nil? or screenshots.length == 0
        ###   report.write "<center>"
        ###   screenshots.each do |screenshot|
        ###     report.write "<a href=\"#{screenshot[0]}\">\n"
        ###     report.write "<img src=\"#{screenshot[0]}\" width=200 height=200 border=2 />\n"
        ###     report.write "</a>\n"
        ###   end
        ###   report.write "</center>"
        ### end

        report.write("        <table width=\"100%\">
                <tr>
                        <td style=\"width:70px\" valign=\"top\" ><b>port</b></td>
                        <td style=\"width:70px\" valign=\"top\" ><b>source</b></td>
                        <td style=\"width:150px\"><b>service</b></td>
                        <td><b>info</b></td>
                </tr>
        </table>\n")

        services = db.execute( "SELECT id,port,service FROM port_info WHERE ip = ? ORDER BY port", ip[0] )
        services.each do |service|
          port = service[1]
          info = service[2]
          report.write("<div onclick=\"javascript:hideshow('service_#{ip[0]}_#{port}');\">
        <table width=\"100%\">
                <tr>
                        <td style=\"width:70px\" valign=\"top\">#{port}</td>
                        <td style=\"width:70px\" valign=\"top\"></td>
                        <td style=\"width:150px\"></td>
                        <td>#{info}</td>
                </tr>
        </table>\n")

          report.write("<div id=\"service_#{ip[0]}_#{port}\" style=\"display: none\">
        <table width=\"100%\">\n")
          infos = db.execute( "SELECT DISTINCT title,data,source FROM service_info WHERE id = ?", service[0] )
          infos.each do |i|
            source  = i[2]
            service = i[0]
            info    = i[1]
            report.write("      <tr>
        	        <td style=\"width:70px\"></td>
                        <td style=\"width:70px\" valign=\"top\">#{source}</td>
        	        <td style=\"width:150px\" valign=\"top\">#{service}</td>")
            if service == "screenshot"
              report.write "<td>\n"
              report.write "       <a  href=\"#{info}\">\n"
              report.write "       <img src=\"#{info}\" width=200 height=200 border=2 />\n"
              report.write "       </a>\n"
              report.write "</td>"
            else
              report.write "<td>#{info.to_html}</td>"
            end

            report.write("     	</tr>\n")
          end

          report.write("        </table>
</div>
</div>\n")
        end

        report.write("</div>\n")

      end

    end

    report.write(SQLITE_REPORT_HEADER)
    report.close()

  end

end

end


if $0 == __FILE__


  options = {}

  opts = OptionParser.new
  opts.banner = "Usage: #{$0} [options] sqlite_file1 <sqlite_file2> <sqlite_file3> ..."

  opts.on("-o", "--output OUTPUT", "The output file") do |o|
    options[:output] = o
  end

  opts.on("--filter-local", "Remove local IP from the list of parsed files") do
    options[:filter] = Proc.new do |x|
      res = false
      res = true if x.match(/^(10|127|192\.168)\./)
      res
    end
  end

  opts.on("-d", "--debug") do
    $debug = true
  end

  opts.on("-f", "--force", "Force report overwrite") do
    options[:force] = true
  end

  opts.parse!

  if options[:output].nil?
    if ARGV.length == 1
      options[:output] = File.basename(ARGV[0], File.extname(ARGV[0])) + ".html"
    else
      options[:output] = "sqlite_report.html"
    end
  end

  options[:files] = ARGV

  Gul::HTML::sqlite_report(options)

end
