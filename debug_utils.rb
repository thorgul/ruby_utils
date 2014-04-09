#!/usr/bin/env ruby

$color=true
$color=false unless RUBY_PLATFORM.match("w32").nil?

$debug=false

def colorize(color, text)
  return "#{color}#{text}\033[0m" if $color == true
  text
end

def black(text);           colorize("\033[30m", text); end
def red(text);             colorize("\033[31m", text); end
def green(text);           colorize("\033[32m", text); end
def yellow(text);          colorize("\033[33m", text); end
def blue(text);            colorize("\033[34m", text); end
def magenta(text);         colorize("\033[35m", text); end
def cyan(text);            colorize("\033[36m", text); end
def white(text);           colorize("\033[37m", text); end

def print_debug(msg)
  print_msg("[#{cyan('?')}]", msg) if $debug == true
end

def print_info(msg)
  print_msg("[#{blue('-')}]", msg)
end

def print_ok(msg)
  print_msg("[#{green('+')}]", msg)
end

def print_error(msg)
  print_msg("[#{red('!')}]", msg)
end

def print_msg(tok, msg)
  puts "#{tok} #{msg}"
end
