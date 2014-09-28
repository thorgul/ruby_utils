require 'json'
require 'selenium-webdriver'
require 'debug-utils'

module Gul

class Browser

  def initialize(opts=nil)

    if opts.nil?
      print_info("No opts given, using default parameters.")
      print_debug("Here is a profile exemple:")
      print_debug("profile = Selenium::WebDriver::Firefox::Profile.new \"C:\\Documents and Settings\\gul\\Application Data\\Mozilla\\Firefox\\Profiles\\selenium\"")
      print_debug("profile['general.useragent.override']  = \"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)\"")
      print_debug("profile['general.useragent.vendor']    = \"\"")
      print_debug("profile['general.useragent.vendorSub'] = \"\"")
      opts = {}
    end

    if opts[:browser].nil?
      print_debug("No browser specified, defaulting to Internet Explorer")
      opts[:browser] = :ie
    end

    @profile = opts[:profile]
    print_debug("No profile selected, using the default one") if @profile.nil?

    selenium_opts = {}
    selenium_opts[:profile] = @profile unless @profile.nil?

    @browser = Selenium::WebDriver.for opts[:browser], selenium_opts

    # browser.execute_script("alert('Go to https://src-linky.erdfdistribution.fr/ to activate the token !')")
  end

  # prefix => SRC_LINKY_IHM_WEB/
  def fuzz(opts={})

    if @browser.nil?
      print_error("Something wrong appenned with the browser")
      return false
    end

    base_dir = "#{ENV['HOME']}/current"
    base_dir = "#{ENV['HOME']}/Desktop/current" if not RUBY_PLATFORM.match("w32").nil?

    opts[:prefix] = "" if opts[:prefix].nil?
    opts[:dico]   = "#{base_dir}/dico/fuzz.txt" if opts[:dico].nil?

    unless File.readable? opts[:dico]
      print_error "Dictionnary => #{opts[:dico]}: no such file or directory"
      return false
    end

    opts[:screenshots]       = {} if opts[:screenshots].nil?
    opts[:screenshots][:dir]    = "#{base_dir}/screenshots" if opts[:screenshots][:dir].nil?
    opts[:screenshots][:prefix] = "#{Time.new.strftime("%Y-%m-%d_%H-%M-%S")}_#{opts[:screenshots][:prefix]}_"
    opts[:screenshots][:index]  = "#{opts[:screenshots][:dir]}/#{opts[:screenshots][:prefix]}__index.txt"

    return false unless File.exist?(opts[:dico])

    if opts[:lambda].nil? and not opts[:url].nil?

      opts[:lambda] = Proc.new do |url, except|
        @browser.get #{url}
        except.each do |e|
          next if @browser.page_source.downcase.include? e
        end
      end

    end

    if opts[:lambda].nil?
      print_error "No Lambda found for fuzzing. Dying :/"
      return false
    end

    fuzz = open(opts[:dico])
    index = open(opts[:screenshots][:index], 'w')

    i = 0
    fuzz.readlines.each do |line|
      line.chomp!

      begin

        check_page = opts[:lambda].call "#{opts[:url]}/#{line}", ["error 404", "error 403"]

        index.write("%04x => #{line}\n" % i)
        index.flush
        opts[:browser].save_screenshot("#{opts[:screenshots][:dir]}/#{opts[:screenshots][:prefix]}_%04x.png" % i)

        i += 1
      rescue Exception => e
        puts "Got a #{e} while wrong while processing #{opts[:url]}/#{line}"
      end

    end

    fuzz.close
    index.close
    true
  end

end
end
