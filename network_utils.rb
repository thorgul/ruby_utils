require 'socket'


def hex_to_ipv4_addr(hexa)
  return nil if hexa.length != 8
  hexa.scan(/../).reverse.map{|x| x.to_i(16)}.join(".")
end

def get_default_route(type = :addr)
  unless type == :addr or type == :iface
    puts "get_default_route: Bad type !!!"
    return nil
  end
  r = File.open("/proc/net/route")
  data = r.read()
  rows = data.split("\n")
  
  rows.each do |r|

    columns = r.split("\t")
    unless columns[2].to_i == 0
      return columns[0] if type == :iface
      return hex_to_ipv4_addr(columns[2])
    end

  end
  return nil
end

def get_default_ipv4_addr()

  default_iface = get_default_route(:iface)
  Socket.getifaddrs.each do |a|
    return a.addr.ip_address if a.addr.ipv4? and a.name == default_iface
  end
  nil
end

def get_first_private_ipv4
  Socket.ip_address_list.detect do |intf|
    intf.ipv4_private?
  end
end

def get_first_public_ipv4
  Socket.ip_address_list.detect do |intf|
    intf.ipv4?              and
      !intf.ipv4_loopback?  and
      !intf.ipv4_multicast? and
      !intf.ipv4_private?
  end
end
