#!/usr/bin/env ruby
#
# Need to scrap ideas from:
# - http://cutycapt.sourceforge.net/
# - https://github.com/paulhammond/webkit2png/

require 'Qt'
require 'qtwebkit'
require 'uri'

module Gul

  def self.url_to_filename(path)
    path.gsub('/', '_')
  end

  class WebView < Qt::WebView

    attr_accessor :loaded, :url

    def initialize(opts)
      super()
      @loaded = false
      @output = opts[:output].nil? ? "/tmp/test.png" : opts[:output]
      @url = opts[:url]
      @app = opts[:app]
    end

    def screenshot(url=nil, output=nil)
      @url = url       unless url.nil?
      @output = output unless output.nil?

      self.load Qt::Url.new(url)
      self.show
      self.load_wait()

      win = Qt::Pixmap.grabWindow(self.winId)
      win.save(@output)
      @loaded = false
    end

    def sig(signal, &blk)
      connect(signal, &blk)
    end

    def load_wait(delay=1)
      while @loaded == false
        @app.processEvents()
        sleep(delay)
      end
    end

  end

  class Webkit

    # Open a web page in webkit
    # ==== Attributes
    #
    # * +:url+ - The url at which the page should be opened
    # * +:fullscreen+ - Defines if the page will be opened in fullscreen mode
    # * +:lambda+ - In case you wanna do something after the page is opened (like a screenshot)

    def self.screenshot(opts)
      if opts.nil? or opts[:url].nil?
        print_error "No URL given in :url parameter. Are you dumb ?"
        return nil
      end

      # Ignore SSL Errors by setting CURLOPT_SSL_VERIFYPEER
      # cf. Source\WebCore\platform\network\curl\ResourceHandleManager.cpp
      #     Lines 65 and 681
      ENV['WEBKIT_IGNORE_SSL_ERRORS'] = "1"

      app = Qt::Application.new([])
      app.objectName = "WebKit Page on #{opts[:url]}"

      opts[:app] = app
      urls = []

      case opts[:url]
      when Array
        urls = opts[:url]
      when String
        urls = [ opts[:url] ]
      end

      urls.map! do |u|
        u = "http://#{u}" unless u.start_with? "http"
        u
      end

      webkit_page = Kernel.fork do

        # Prolly useless, but just to be sure.
        # ENV['WEBKIT_IGNORE_SSL_ERRORS'] = "1"

        view = Gul::WebView.new(opts)
        view.windowTitle = "Screenshots in progress"

        view.showFullScreen if opts[:fullscreen]

        view.sig(SIGNAL('loadFinished(bool)')) {|x| view.loaded = true}

        urls.each do |url|
          uparse = URI.parse(url)
          path = "screenshot_#{uparse.host}:#{uparse.port}"
          path << Gul::url_to_filename(uparse.path.to_s)        unless uparse.path.nil?
          path << '?' + Gul::url_to_filename(uparse.query.to_s) unless uparse.query.nil?
          path << ".png"
          view.screenshot(url, path)
        end

        app.exec
      end

      Process.detach(webkit_page) unless webkit_page.nil?

    end

  end

end


if $0 == __FILE__
  fullscreen = false
  if ARGV[0] == '-f'
    fullscreen = true
    ARGV.shift
  end
  Gul::Webkit.screenshot(:url => ARGV, :fullscreen => fullscreen)
end
