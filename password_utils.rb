#!/usr/bin/env ruby

require 'crypto_utils'

module Password

module Cisco

$xlat=[
	0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
	0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
	0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
	0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36,
	0x39, 0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76,
	0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b,
	0x3b, 0x66, 0x67, 0x38, 0x37
]

  def self.encrypt(password)
    seed=rand(16)
    password=password[0, 11]

    hash=(0 .. (password.length-1)).collect { |i| $xlat[(seed+i)%$xlat.length] ^ password[i] }

    return format("%02d", seed) + hash.collect { |e| format("%02x", e) }.join("")
  end

  def self.decrypt(hash)
    seed=hash[0, 2].to_i
    hash=hash[2, hash.length-1]
    pairs=(0 .. (hash.length/2-1)).collect { |i| hash[i*2, 2].to_i(16) }
    decrypted=(0 .. (pairs.length-1)).collect { |i| $xlat[(seed+i)%$xlat.length] ^ pairs[i] }

    return (decrypted.collect { |e| e.chr }).join("")
  end

end

module CPassword

  $key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9" +
         "\xfa\xf4\x93\x10\x62\x0f\xfe\xe8" +
         "\xf4\x96\xe8\x06\xcc\x05\x79\x90" +
         "\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"

  def self.decrypt(hash)
    res = nil

    3.times do |pad|
      begin
        aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
        aes.decrypt
        aes.key = $key
        test_hash = hash + "=" * pad
        res = aes.update(test_hash.base64_decode) + aes.final

        res = res.gsub!(/\x00/, '')
        break
      rescue
      end
    end
    res
  end

  def self.encrypt(password)
    aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
    aes.encrypt
    aes.key = $key
    uni_pass = password.each_byte.map{|x| "#{x.chr}\x00" }.join
    res = aes.update(uni_pass) + aes.final
    res.base64_encode.gsub(/=+\n$/, "")
  end

end

end

if $0 == __FILE__
  ARGV.each { |arg| pass = arg.strip ; puts Password::Cisco.decrypt(pass) + ": (#{pass})" }
end
