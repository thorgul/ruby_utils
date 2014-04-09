#!/usr/bin/env ruby

require 'openssl'


def unpack_then_64(str=nil)
  return nil if str.nil?
  [ str.unhex ].pack("m0*").delete "\n"
end

class String

  # Allows strings to get xored !
  def ^(key)
    key = key.to_str
    result = ""
    # puts "length => %d" % length
    for i in 0..length-1
      result << (self[i].ord ^ key[i % key.length].ord).chr
    end
    result
  end

  def to_hex()
    self.unpack('H*')[0]
  end

  def unhex()
    [self].pack("H*")
  end

  def to_bin()
    self.unpack('B*')[0]
  end

  def unbin()
    [self].pack("B*")
  end

  def base64_encode()
    [ self ].pack("m*")
  end

  def base64_decode()
    self.unpack("m*")[0]
  end

  def md5
    Digest::MD5.digest(self).hexify
  end

  def sha1
    Digest::SHA1.digest(self).hexify
  end

  def sha256
    Digest::SHA256.digest(self).hexify
  end

  def sha512
    Digest::SHA512.digest(self).hexify
  end


  def rot13()
    self.tr "A-Za-z", "N-ZA-Mn-za-m"
  end

  def char_freq
    len = self.length()
    a = self.chars.chunk{|i| i}.map{|m,n| [m, Float(n.count(m)) / len]}
    ret = {}
    a.each do |k,v|
      if ret[k].nil?
        ret[k] = v
      else
        ret[k] += v
      end
    end

    ret
  end

  def char_frequency

    res = {}

    self.chars.sort.chunk{|i| i }.map do |m,n|
      res[m] = Float(n.count(m)) / self.length()
    end

    res

  end

  def hamming(str=nil)

    return nil if str.nil?

    if self.length != str.length
      puts "Can't calculate hamming distance with unequal string size (#{str.length} for #{self.length})"
      return nil
    end

    bself = self.unpack("B*")[0]
    bstr  = str.unpack("B*")[0]
    dist  = 0

    0.upto(bself.length - 1) do |index|
      dist += 1 if bself[index] != bstr[index]
    end

    dist
  end

  def get_xor_key(opts={})

    val = [0, 0]

    1.upto(255) do |x|
      xored = self ^ x.chr
      fail = false

      xored.each_byte do |y|
        if  ( y >= 0x00 and y <= 0x08) or
            ( y >= 0x0b and y <= 0x0c) or
            ( y >= 0x0e and y <= 0x1f) or
            ( y >= 0x7f)
          fail = true
        end
      end

      next if fail == true

      c = letters_frequency_score(xored)
      val = [x, c] if c > val[1]
    end

    return nil if val == [0, 0]
    val[0].chr
  end

  def letters_frequency_score(base = Crypto::Frequency::EnglishLettersWithSpace, threshold=0.07)

    score = Float(self.length())

    self.downcase.freq.each do |k,v|
      unless base[k].nil?

        if (v - base[k]).abs < threshold
          score -= (v - base[k]).abs
        end

      else
        score -= 1
      end
    end

    score /= self.length()
    score
  end

  def pad(size, round_up=false)
    padding = size - (self.length % size)
    padding = 0 if padding == size and round_up == false

    self + padding.chr * padding
  end

  def pad!(size)
    replace self.pad(size)
  end

  def pkcs7_unpad()
    pad = self[-1].ord
    unless pad <= 16 and self[-pad, pad].pkcs7_padding?
      raise "Not a PKCS7 padding!"
    end
    self[0,self.length - pad]
  end

  def pkcs7_padding?()
    pad = self[0].ord
    return false unless self.length == pad
    self.each_byte do |b|
      return false unless b.ord == pad
    end
    true
  end

end # String


module Crypto

module Frequency

EnglishLetters = {
    "a" => 0.08167,
    "b" => 0.01492,
    "c" => 0.02782,
    "d" => 0.04253,
    "e" => 0.12702,
    "f" => 0.02228,
    "g" => 0.02015,
    "h" => 0.06094,
    "i" => 0.06966,
    "j" => 0.00153,
    "k" => 0.00772,
    "l" => 0.04025,
    "m" => 0.02406,
    "n" => 0.06749,
    "o" => 0.07507,
    "p" => 0.01929,
    "q" => 0.00095,
    "r" => 0.05987,
    "s" => 0.06327,
    "t" => 0.09056,
    "u" => 0.02758,
    "v" => 0.00978,
    "w" => 0.02360,
    "x" => 0.00150,
    "y" => 0.01974,
    "z" => 0.00074
}

EnglishLettersWithSpace = {
    " " => 0.1828846265,
    "a" => 0.0653216702,
    "b" => 0.0125888074,
    "c" => 0.0223367596,
    "d" => 0.0328292310,
    "e" => 0.1026665037,
    "f" => 0.0198306716,
    "g" => 0.0162490441,
    "h" => 0.0497856396,
    "i" => 0.0566844326,
    "j" => 0.0009752181,
    "k" => 0.0056096272,
    "l" => 0.0331754796,
    "m" => 0.0202656783,
    "n" => 0.0571201113,
    "o" => 0.0615957725,
    "p" => 0.0150432428,
    "q" => 0.0008367550,
    "r" => 0.0498790855,
    "s" => 0.0531700534,
    "t" => 0.0751699827,
    "u" => 0.0227579536,
    "v" => 0.0079611644,
    "w" => 0.0170389377,
    "x" => 0.0014092016,
    "y" => 0.0142766662,
    "z" => 0.0005128469
  }

EnglishWordFirstLetter = {
    "a" => 0.11602,
    "b" => 0.04702,
    "c" => 0.03511,
    "d" => 0.02670,
    "e" => 0.02007,
    "f" => 0.03779,
    "g" => 0.01950,
    "h" => 0.07232,
    "i" => 0.06286,
    "j" => 0.00597,
    "k" => 0.00590,
    "l" => 0.02705,
    "m" => 0.04374,
    "n" => 0.02365,
    "o" => 0.06264,
    "p" => 0.02545,
    "q" => 0.00173,
    "r" => 0.01653,
    "s" => 0.07755,
    "t" => 0.16671,
    "u" => 0.01487,
    "v" => 0.00649,
    "w" => 0.06753,
    "x" => 0.00037,
    "y" => 0.01620,
    "z" => 0.00034
  }
end

module CBC

  module_function

  def encrypt(opts={})
    chunks = opts[:data].scan(/.{1,16}/m)

    # puts chunks

    last_chunk = opts[:iv]

    chunks.map! do |c|

      b = c.pad(16) ^ last_chunk
      # last_chunk = b ^ opts[:key].pad(16)
      last_chunk = ECB.encrypt(:data => b, :key => opts[:key])[0,16]
    end

    if opts[:data].length % 16 == 0
      chunks.push << ECB.encrypt(:data => "\x10" * 16 ^ last_chunk, :key => opts[:key])[0,16]
    end

    chunks.join()
  end

  def decrypt(opts={})

    chunks = opts[:data].scan(/.{1,16}/m)

    last_chunk = opts[:iv]

    chunks.map! do |c|

      xor = last_chunk
      last_chunk = c.pad(16)
      b = ECB.decrypt(:data => c + ECB.encrypt(:data => "\x10" * 16 ,
                                               :key => opts[:key]),
                      :key  => opts[:key])
      b[0,16] ^ xor

    end

    chunks.join().pkcs7_unpad()
  end

end # Crypto::CBC



module ECB

  module_function

  def encrypt(opts={})

    opts[:cipher] = "AES-128-ECB"      if opts[:cipher].nil?
    opts[:key]    = "YELLOW SUBMARINE" if opts[:key].nil?

    aes = OpenSSL::Cipher::Cipher.new(opts[:cipher])
    aes.encrypt
    aes.key = opts[:key]
    aes.update(opts[:data]) + aes.final
  end

  def decrypt(opts = {})
    opts[:cipher] = "AES-128-ECB"      if opts[:cipher].nil?
    opts[:key]    = "YELLOW SUBMARINE" if opts[:key].nil?

    aes = OpenSSL::Cipher::Cipher.new(opts[:cipher])
    aes.decrypt
    aes.key = opts[:key]
    aes.update(opts[:data]) + aes.final
  end

end # Crypto::ECB


end # Crypto

