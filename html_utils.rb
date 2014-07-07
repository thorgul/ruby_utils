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
      ips = db.execute( "select distinct ip from port_info" )
      ips.sort_by! {|ip| ip.to_s.split('.').map{ |octet| octet.to_i} }
      ips.each do |ip|

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

  output_path = "sqlite_report.html"
  output_path = File.basename(ARGV[0], File.extname(ARGV[0])) + ".html" if ARGV.length == 1

  Gul::HTML::sqlite_report(:files => ARGV, :output => output_path)

end
