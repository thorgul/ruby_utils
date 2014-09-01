#!/usr/bin/env ruby

require 'sqlite3'

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

  def self.sqlite_report_service(db, report, sqlquery, name=nil)
    res = db.execute( sqlquery )

    return if res.nil? or res.length == 0

    report.write("<div id=\"boxtitle\" onclick=\"javascript:hideshow('#{name} Servers');\" style=\"background-color:#ffaa44\">")
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
                        <td style=\"width:150px\" valign=\"top\" >#{unit[1]}</td>
                        <td>#{unit[2]}</td>
                </tr>
        </table>\n")
      end
      report.write("</div>\n")
  end

  def self.sqlite_report(opts)
    files = opts[:files]
    files = [ opts[:files] ] if files.class == String

    if File.exists?(opts[:output])
      puts "#{opts[:output]} exists, no override, sorry"
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

      # Important Web Servers
      sqlite_report_service(db, report, "select distinct ip, port, service from port_info LEFT JOIN service_info ON port_info.id=service_info.id where " +
                                        "port_info.port = 80 and (port_info.service like '%Lotus Domino%' or service_info.title like '%Lotus Domino%') order by service", "Interesting Web Servers")

      # Databases
      sqlite_report_service(db, report, "select ip, port, service from port_info LEFT JOIN service_info ON port_info.id=service_info.id where " +
                                        "port_info.service like '%sql%'    or service_info.title like '%sql%'    or " +
                                        "port_info.service like '%access%' or service_info.title like '%access%' or " +
                                        "port_info.service like '%db2%'    or service_info.title like '%db2%' order by service", "Databases")

      # Tomcat Servers
      sqlite_report_service(db, report, "select ip, port, data from port_info JOIN service_info ON port_info.id=service_info.id where " +
                                        "service like '%tomcat%' and service_info.title = 'http-title' order by data", "Tomcat")

      # VNC
      sqlite_report_service(db, report, "select ip, port, data from port_info JOIN service_info ON port_info.id=service_info.id where " +
                                        "service like '%VNC%' and service_info.title != 'http-title' order by data", "VNC")


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

        report.write("        <table width=\"100%\">
                <tr>
                        <td style=\"width:70px\" valign=\"top\" ><b>port</b></td>
                        <td style=\"width:70px\" valign=\"top\" ><b>source</b></td>
                        <td style=\"width:150px\"><b>service</b></td>
                        <td><b>info</b></td>
                </tr>
        </table>\n")

        services = db.execute( "select id,port,service from port_info where ip = ? order by port", ip[0] )
        services.each do |service|
          report.write("<div onclick=\"javascript:hideshow('service_#{ip[0]}_#{service[1]}');\">
        <table width=\"100%\">
                <tr>
                        <td style=\"width:70px\" valign=\"top\">#{service[1]}</td>
                        <td style=\"width:70px\" valign=\"top\"></td>
                        <td style=\"width:150px\"></td>
                        <td>#{service[2]}</td>
                </tr>
        </table>\n")

          report.write("<div id=\"service_#{ip[0]}_#{service[1]}\" style=\"display: none\">
        <table width=\"100%\">\n")
          infos = db.execute( "select distinct title,data,source from service_info where id = ?", service[0] )
          infos.each do |info|
            report.write("      <tr>
        	        <td style=\"width:70px\"></td>
                        <td style=\"width:70px\" valign=\"top\">#{info[2]}</td>
        	        <td style=\"width:150px\" valign=\"top\">#{info[0]}</td>
        	        <td>#{info[1].gsub(/\r?\n/, "<br>\n")}</td>
        	</tr>\n")
          end

          report.write("        </table>
</div>
</div>\n")
        end

        report.write("</div>\n")

      end

      report.write(SQLITE_REPORT_HEADER)
      report.close()

    end
  end

end

end


if $0 == __FILE__

  abort "Usage is #$0: sqlite_file1 <sqlite_file2> <sqlite_file3> ..." if ARGV.length == 0

  filter = nil

  if ARGV.length > 2 and ARGV[0] == "--filter"

    if ARGV[1] == "local"
      filter = Proc.new do |x|
        res = false
        res = true if x.match(/^(10|127|192\.168)\./)
        res
      end
    end

    ARGV.shift
    ARGV.shift
  end


  output_path = "sqlite_report.html"
  output_path = File.basename(ARGV[0], File.extname(ARGV[0])) + ".html" if ARGV.length == 1

  Gul::HTML::sqlite_report(:files => ARGV, :output => output_path, :filter => filter)

end
