#!/usr/bin/env ruby

$color=true
$color=false unless RUBY_PLATFORM.match("w32").nil?

$debug=false

def colorize(color, text)
  return "#{color}#{text}\x1b[0m" if $color == true
  text
end

def black(text);           colorize("\x1b[30;1m", text); end
def red(text);             colorize("\x1b[31;1m", text); end
def green(text);           colorize("\x1b[32;1m", text); end
def yellow(text);          colorize("\x1b[33;1m", text); end
def blue(text);            colorize("\x1b[34;1m", text); end
def magenta(text);         colorize("\x1b[35;1m", text); end
def cyan(text);            colorize("\x1b[36;1m", text); end
def white(text);           colorize("\x1b[37;1m", text); end

def print_debug(msg)
  print_msg("[#{blue('DEBUG')}]", msg) if $debug == true
end

def print_info(msg)
  print_msg("[#{cyan('INFO')}]", msg)
end

def print_ok(msg)
  print_msg("[#{green('SUCCESS')}]", msg)
end

def print_nok(msg)
  print_msg("[#{magenta('FAIL')}]", msg)
end

def print_warn(msg)
  print_msg("[#{yellow('WARN')}]", msg)
end

def print_error(msg)
  print_msg("[#{red('ERROR')}]", msg)
end

def print_msg(tok, msg)
  puts "#{tok} #{msg}"
end
