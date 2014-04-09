#!/usr/bin/env ruby

require 'mini_exiftool'

module Gul

  class Gallery

    def initialize(opts={})
      @path    = opts[:path].nil?   ? './index.html' : opts[:path]
      @img_dir = opts[:imgs].nil?   ? './'           : opts[:imgs]
      @width   = opts[:width].nil?  ? 400            : opts[:width]
      @height  = opts[:height].nil? ? 400            : opts[:height]
    end

    def generate()
      data = gen_pics_data()

      html_page = "<head>
</head>
<body>
<center>
#{data}
</center>
</body>
"

      f = File.open(@path, 'w')
      f.write(html_page)
      f.close
    end

    def get_file_source(file)
      exif = MiniExiftool.new(file)
      exif["http-src"].nil? ? file : exif["http-src"]
    end

    def gen_pics_data()
      data = ""
      begin
        matches = Dir.glob("#{@img_dir}/*.{png,jpg,jpeg}")
        data = matches.map do |img|
          source = get_file_source(img)
          line =  "<a href=\"#{source}\">\n"
          line << "<img src=\"#{img}\" width=#{@width} height=#{@height} />\n"
          line << "</a>\n"
          line
        end
        # puts data
      rescue SystemCallError => e
        data = ["<b>#{e}</b>"]
      end
      data.join
    end

  end
end


if __FILE__ == $0
  gallery = Gul::Gallery.new()
  gallery.generate
end

