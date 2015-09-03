#!/usr/bin/env ruby

require 'crypto_utils'

# Todo
# Implement Jenkins password decryption
# https://github.com/tweksteen/jenkins-decrypt/blob/master/decrypt.py

module Password

module Cisco

module Password7

  module_function

  @@xlat=[
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
    0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
    0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
    0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36,
    0x39, 0x38, 0x33, 0x34, 0x6e, 0x63, 0x78, 0x76,
    0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6b,
    0x3b, 0x66, 0x67, 0x38, 0x37
  ]

  def encrypt(password)
    seed=rand(16)
    password=password[0, 11]

    hash=(0 .. (password.length-1)).collect { |i| @@xlat[(seed+i) % @@xlat.length] ^ password[i] }

    return format("%02d", seed) + hash.collect { |e| format("%02x", e) }.join("")
  end

  def decrypt(hash)
    seed=hash[0, 2].to_i
    hash=hash[2, hash.length-1]
    pairs=(0 .. (hash.length/2-1)).collect { |i| hash[i*2, 2].to_i(16) }
    decrypted=(0 .. (pairs.length-1)).collect { |i| @@xlat[(seed+i) % @@xlat.length] ^ pairs[i] }

    return (decrypted.collect { |e| e.chr }).join("")
  end

end

module WLC

  module_function

  def decrypt(iv, hash)

    hash.gsub!(/0*$/, "")

    aes = OpenSSL::Cipher::Cipher.new("AES-128-CBC")
    aes.decrypt
    aes.key = "834156F9940F09C0A8D00F019F850005".unhex
    aes.iv  = iv.unhex
    aes.update(hash.unhex) + aes.final

  end

end

module ACS

  module_function

  # ripped from nico's script http://www.openwall.com/lists/john-users/2014/12/08/1
  def decrypt(enc)

    des = OpenSSL::Cipher::Cipher.new('DES-EDE3-CBC')
    des.decrypt
    des.key = "7304912f3d62b5efcd837373bf6b7ff4f1f438b6b67008ef".unhex
    des.iv  = "0a0a0a0a0a0a0a0a".unhex
    des.padding = 0

    # libCARSReposMgr.so 3DES padding handling is wrong...
    # we try to mimick the behavior here.
    enc += "00" * ( 8 - ( (enc.length / 2) & 7 ) )

    decrypted_passwd = des.update(enc.unhex) + des.final
    decrypted_passwd.gsub(/\x00.*/, '')

  end

end

end

module Citrix

  # Doc is there => https://intrepidusgroup.com/insight/2014/01/good-fun-with-bad-crypto/
  module Ctx1

    module_function

    def decrypt_letter(block, v = 0)
      f = (block[2].ord - 1) & 0x0f
      s = (block[3].ord - 1) & 0x0f
      ((f*16+s) ^ v).chr
    end

    def decrypt(password)

      clear = ""
      v = 0

      password.scan(/..../).each do |block|
        c = Citrix::Ctx1.decrypt_letter(block, v)
        v = v ^ c.ord
        clear << c
      end
      clear

    end

  end

end

module CPassword

  @@key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9" +
         "\xfa\xf4\x93\x10\x62\x0f\xfe\xe8" +
         "\xf4\x96\xe8\x06\xcc\x05\x79\x90" +
         "\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"

  module_function

  def decrypt(hash)
    res = nil

    3.times do |pad|
      begin
        aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
        aes.decrypt
        aes.key = @@key
        test_hash = hash + "=" * pad
        res = aes.update(test_hash.base64_decode) + aes.final
        res = res.gsub!(/\x00/, '')
        break
      rescue
      end
    end
    res
  end

  def encrypt(password)
    aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
    aes.encrypt
    aes.key = @@key
    uni_pass = password.each_byte.map{|x| "#{x.chr}\x00" }.join
    res = aes.update(uni_pass) + aes.final
    res.base64_encode.gsub(/=+\n$/, "")
  end

end

module NTSSP

  module_function
  
  def decode(pass, base64 = true)

    pass = pass.base64_decode if base64 == true
    pass = pass.force_encoding(Encoding::BINARY)

    lmHashLen    = pass[12..13].unpack('S<')[0].to_i
    lmHashOffset = pass[16..17].unpack('S<')[0].to_i
    puts "lmHashLen:    %s" % lmHashLen                if $debug
    puts "lmHashOffset: %s" % lmHashOffset             if $debug
    lmHash       = pass[lmHashOffset..lmHashOffset+lmHashLen-1].unpack('H*')[0].upcase
    puts "lmHash;       %s" % lmHash                   if $debug
    ntHashLen    = pass[20..21].unpack('S<')[0].to_i
    ntHashOffset = pass[24..25].unpack('S<')[0].to_i
    puts "ntHashLen;    %s" % ntHashLen                if $debug
    puts "ntHashOffset: %s" % ntHashOffset             if $debug
    ntHash       = pass[ntHashOffset..ntHashOffset+ntHashLen-1].unpack('H*')[0].upcase
    puts "ntHash:       %s" % ntHash                   if $debug
    userLen      = pass[36..37].unpack('S<')[0].to_i
    userOffset   = pass[40..41].unpack('S<')[0].to_i
    puts "userLen:      %s" % userLen                  if $debug
    puts "userOffset:   %s" % userOffset               if $debug
    user         = pass[userOffset..userOffset+userLen-1].gsub("\x00",'')
    puts "user:         %s" % user                     if $debug
    # print User
    # print NthashLen
    ntHashLen      = 64
    domainLen      = pass[28..29].unpack('S<')[0]
    domainOffset   = pass[32..33].unpack('S<')[0]
    domain         = pass[domainOffset..domainOffset+domainLen-1].gsub("\x00",'')
    hostNameLen    = pass[44..45].unpack('S<')[0]
    hostNameOffset = pass[48..49].unpack('S<')[0]
    hostName       = pass[hostNameOffset..hostNameOffset+hostNameLen-1].gsub("\x00",'')
    res = '%s::%s::%s:%s' % [user, domain, ntHash[0..31], ntHash[32..-1]]
  end
  
end

module WebSphere

  module Xor

    module_function

    def decipher ( pass )

      res = String.new

      return nil if pass.match(/^\{(xor)\}.*/).nil?

      b64pass = pass.scan(/^\{xor\}(.*)/)[0][0]

      xored = b64pass.base64_decode
      res = xored ^ "_"

      res
    end

  end

end


module WebLogic

  module Aes

    # Thanks to that dude that finiehed my old abandonned research
    # https://blog.netspi.com/decrypting-weblogic-passwords/
    @@hardcoded_key = "ccb97558940b82637c8bec3c770f86fa3a391a56".unhex()
    
    module_function

    # pass={AES}.....
    def decipher ( pass, key )

      puts     "key [0x#{key.length.to_s(16)}]     => #{key.to_hex}"


      pass      = pass[5..-1]        if pass.start_with? "{AES}"
      enc_pass  = pass.base64_decode
      puts     "enc_pass [0x#{enc_pass.length.to_s(16)}] => #{enc_pass.to_hex}"
      
      #all call the password => @@key

      index = 0

      nb          = key[index].to_hex.to_i(16)
      index       += 1
                  
      salt        = key[index..index + nb - 1]
      index       += nb
      puts        "nb              => 0x#{nb.to_s(16)}"                          if $debug
      puts        "index           => 0x#{index.to_s(16)}"                       if $debug
      puts        "salt [0x#{salt.length.to_s(16)}]      => #{salt.to_hex}"      if $debug
                  
      enc_type    = key[index].to_hex.to_i(16)
      index       += 1
      puts        "nb              => 0x#{nb.to_s(16)}"                          if $debug
      puts        "index           => 0x#{index.to_s(16)}"                       if $debug
      puts        "enc_type        => #{enc_type}"                               if $debug
                  
      nb          = key[index].to_hex.to_i(16)
      index       += 1

      enc_key     = key[index..index + nb - 1]
      index +=    nb
      puts        " -=[ 3DES ]=-"
      puts        "nb              => 0x#{nb.to_s(16)}"                          if $debug
      puts        "index           => 0x#{index.to_s(16)}"                       if $debug
      puts        "enc_key [0x#{enc_key.length.to_s(16)}]  => #{enc_key.to_hex}" if $debug

      if enc_type >= 2
        nb        = key[index].to_hex.to_i(16)
        index       += 1

        enc_key   = key[index..index + nb - 1]
        puts      " -=[ AES ]=-"
        puts      "nb              => 0x#{nb.to_s(16)}"                          if $debug
        puts      "index           => 0x#{index.to_s(16)} -> 0x#{(index + nb).to_s(16)}"  if $debug
        puts      "enc_key [0x#{enc_key.length.to_s(16)}]  => #{enc_key.to_hex}" if $debug
      end

      ### # On va tester ca...
      ### # rc2-cbc
      ### # sinon tester ca :
      ### # aes-128-cbc-hmac-sha1
      ### aes = OpenSSL::Cipher::Cipher.new('rc2-cbc')
      ### 
      ### 
      ### aes.decrypt
      ### aes.key = @@key
      ### aes.iv  = salt

      secret_key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(@@hardcoded_key,
                                                   salt,
                                                   5, # Thx Eric Gruber !
                                                   @@hardcoded_key.length)
      puts "sec key [0x#{secret_key.length.to_s(16)}]  => #{secret_key.to_hex}"

      cipher = OpenSSL::Cipher.new('AES-128-CBC')
      cipher.decrypt
      cipher.key = secret_key
      cipher.iv  = enc_pass[0..15]
      # cipher.padding = 0

      res = cipher.update(enc_pass[16..-1]) + cipher.final
      # res.to_hex

      ###  SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWITHSHAAND128BITRC2-CBC");
      ### 
      ###  PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 5);
      ### 
      ###  SecretKey secretKey = keyFactory.generateSecret(pbeKeySpec);
      ### 
      ###  PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 0);
      ### 
      ###  Cipher cipher = Cipher.getInstance("PBEWITHSHAAND128BITRC2-CBC");
      ###  cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
      ###  SecretKeySpec secretKeySpec = new SecretKeySpec(cipher.doFinal(encryptionKey), "AES");
      ### 
      ###  byte[] iv = new byte[16];
      ###  System.arraycopy(encryptedPassword1, 0, iv, 0, 16);
      ###  int encryptedPasswordlength = encryptedPassword1.length - 16 ;
      ###  byte[] encryptedPassword2 = new byte[encryptedPasswordlength];
      ###  System.arraycopy(encryptedPassword1, 16, encryptedPassword2, 0, encryptedPasswordlength);
      ###  IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      ###  Cipher outCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      ###  outCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
      ### 
      ###  byte[] cleartext = outCipher.doFinal(encryptedPassword2);
      ### 
      ###  return new String(cleartext, "UTF-8");
      ###  }

      
      
      
    end

  end  # WebLogic:Aes

  module Des # Actually 3Des...

    module_function
    def decipher ( pass, key )

    end

  end # WebLogic:Des

end # WebLogic


# Stolen code from somewhere I forgot
# Trash it if you are annoying about licensing and stuff
class VNC

  @@key = [23,82,107,6,35,78,88,7].map{|x| x.chr}.join
  BLOCK_SIZE = 8

  attr_reader :mode

  def initialize mode
    unless [:encrypt, :decrypt].include? mode
      raise ArgumentError, 'invalid mode argument - %s' % mode
    end
    @mode = mode

    @@key = @@key[0, BLOCK_SIZE]
    @@key << 0.chr * (BLOCK_SIZE - @@key.length)
    @key = @@key

    @keys = self.class.send :prepare_key_stage2, self.class.send(:prepare_key_stage1, @@key, mode)

    @buf = ''
  end

  def update data
    result = ''
    data = @buf + data unless @buf.empty?
    num_blocks, residual = data.length.divmod BLOCK_SIZE
    num_blocks.times do |i|
      block = data[i * BLOCK_SIZE, BLOCK_SIZE].unpack('N2')
      result << self.class.send(:desfunc, block, @keys).pack('N2')
    end
    @buf = residual == 0 ? '' : data[-residual..-1]
    result
  end

  def final
    if @buf.empty?
      ''
    else
      update 0.chr * (BLOCK_SIZE - @buf.length)
    end
  end

  def self.encrypt data
    des = new :encrypt
    res = des.update(data) << des.final
    res.to_hex
  end

  def self.decrypt data
    des = new :decrypt
    res = nil
    if data.length == 16
      des.update(data.unhex) << des.final
    else
      des.update(data) << des.final
    end
  end

  class << self #:nodoc: all
    BYTEBIT	= [
                   01, 02, 04, 010, 020, 040, 0100, 0200
                  ]

    BIGBYTE = [
               0x800000, 0x400000, 0x200000, 0x100000,
               0x080000, 0x040000, 0x020000, 0x010000,
               0x008000, 0x004000, 0x002000, 0x001000,
               0x000800, 0x000400, 0x000200, 0x000100,
               0x000080, 0x000040, 0x000020, 0x000010,
               0x000008, 0x000004, 0x000002, 0x000001
              ]

    PC1 = [
           56, 48, 40, 32, 24, 16,  8,	 0, 57, 49, 41, 33, 25, 17,
           9,  1, 58, 50, 42, 34, 26,	18, 10,  2, 59, 51, 43, 35,
           62, 54, 46, 38, 30, 22, 14,	 6, 61, 53, 45, 37, 29, 21,
           13,  5, 60, 52, 44, 36, 28,	20, 12,  4, 27, 19, 11,  3
          ]

    TOTROT = [
              1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
             ]

    PC2 = [
           13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
           22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
           40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
           43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
          ]

    private

    def prepare_key_stage1 key, mode
      pcr = [nil] * 56
      kn = [nil] * 32

      pc1m = (0...56).map do |j|
        l = PC1[j]
        m = l & 07
        (key[l >> 3].ord & BYTEBIT[m]) != 0 ? 1 : 0;
      end

      16.times do |i|
        m = mode == :encrypt ? i << 1 : (15 - i) << 1
        n = m + 1
        kn[m] = kn[n] = 0
        28.times do |j|
          l = (j + TOTROT[i]) % 28
          pcr[j] = pc1m[l]
          pcr[j + 28] = pc1m[l + 28]
        end
        24.times do |j|
          kn[m] |= BIGBYTE[j] if pcr[PC2[j]] != 0
          kn[n] |= BIGBYTE[j] if pcr[PC2[j+24]] != 0
        end
      end

      kn
    end

    def prepare_key_stage2(raw1)
      cook = []

      16.times do |i|
        a = raw1[i * 2 + 0]
        b = raw1[i * 2 + 1]
        x  = (a & 0x00fc0000) << 6
        x |= (a & 0x00000fc0) << 10
        x |= (b & 0x00fc0000) >> 10
        x |= (b & 0x00000fc0) >> 6
        cook << x
        x  = (a & 0x0003f000) << 12
        x	|= (a & 0x0000003f) << 16
        x	|= (b & 0x0003f000) >> 4
        x |= (b & 0x0000003f)
        cook << x
      end

      cook
    end

    SP1 = [
           0x01010400, 0x00000000, 0x00010000, 0x01010404,
           0x01010004, 0x00010404, 0x00000004, 0x00010000,
           0x00000400, 0x01010400, 0x01010404, 0x00000400,
           0x01000404, 0x01010004, 0x01000000, 0x00000004,
           0x00000404, 0x01000400, 0x01000400, 0x00010400,
           0x00010400, 0x01010000, 0x01010000, 0x01000404,
           0x00010004, 0x01000004, 0x01000004, 0x00010004,
           0x00000000, 0x00000404, 0x00010404, 0x01000000,
           0x00010000, 0x01010404, 0x00000004, 0x01010000,
           0x01010400, 0x01000000, 0x01000000, 0x00000400,
           0x01010004, 0x00010000, 0x00010400, 0x01000004,
           0x00000400, 0x00000004, 0x01000404, 0x00010404,
           0x01010404, 0x00010004, 0x01010000, 0x01000404,
           0x01000004, 0x00000404, 0x00010404, 0x01010400,
           0x00000404, 0x01000400, 0x01000400, 0x00000000,
           0x00010004, 0x00010400, 0x00000000, 0x01010004
          ]

    SP2 = [
           0x80108020, 0x80008000, 0x00008000, 0x00108020,
           0x00100000, 0x00000020, 0x80100020, 0x80008020,
           0x80000020, 0x80108020, 0x80108000, 0x80000000,
           0x80008000, 0x00100000, 0x00000020, 0x80100020,
           0x00108000, 0x00100020, 0x80008020, 0x00000000,
           0x80000000, 0x00008000, 0x00108020, 0x80100000,
           0x00100020, 0x80000020, 0x00000000, 0x00108000,
           0x00008020, 0x80108000, 0x80100000, 0x00008020,
           0x00000000, 0x00108020, 0x80100020, 0x00100000,
           0x80008020, 0x80100000, 0x80108000, 0x00008000,
           0x80100000, 0x80008000, 0x00000020, 0x80108020,
           0x00108020, 0x00000020, 0x00008000, 0x80000000,
           0x00008020, 0x80108000, 0x00100000, 0x80000020,
           0x00100020, 0x80008020, 0x80000020, 0x00100020,
           0x00108000, 0x00000000, 0x80008000, 0x00008020,
           0x80000000, 0x80100020, 0x80108020, 0x00108000
          ]

    SP3 = [
           0x00000208, 0x08020200, 0x00000000, 0x08020008,
           0x08000200, 0x00000000, 0x00020208, 0x08000200,
           0x00020008, 0x08000008, 0x08000008, 0x00020000,
           0x08020208, 0x00020008, 0x08020000, 0x00000208,
           0x08000000, 0x00000008, 0x08020200, 0x00000200,
           0x00020200, 0x08020000, 0x08020008, 0x00020208,
           0x08000208, 0x00020200, 0x00020000, 0x08000208,
           0x00000008, 0x08020208, 0x00000200, 0x08000000,
           0x08020200, 0x08000000, 0x00020008, 0x00000208,
           0x00020000, 0x08020200, 0x08000200, 0x00000000,
           0x00000200, 0x00020008, 0x08020208, 0x08000200,
           0x08000008, 0x00000200, 0x00000000, 0x08020008,
           0x08000208, 0x00020000, 0x08000000, 0x08020208,
           0x00000008, 0x00020208, 0x00020200, 0x08000008,
           0x08020000, 0x08000208, 0x00000208, 0x08020000,
           0x00020208, 0x00000008, 0x08020008, 0x00020200
          ]

    SP4 = [
           0x00802001, 0x00002081, 0x00002081, 0x00000080,
           0x00802080, 0x00800081, 0x00800001, 0x00002001,
           0x00000000, 0x00802000, 0x00802000, 0x00802081,
           0x00000081, 0x00000000, 0x00800080, 0x00800001,
           0x00000001, 0x00002000, 0x00800000, 0x00802001,
           0x00000080, 0x00800000, 0x00002001, 0x00002080,
           0x00800081, 0x00000001, 0x00002080, 0x00800080,
           0x00002000, 0x00802080, 0x00802081, 0x00000081,
           0x00800080, 0x00800001, 0x00802000, 0x00802081,
           0x00000081, 0x00000000, 0x00000000, 0x00802000,
           0x00002080, 0x00800080, 0x00800081, 0x00000001,
           0x00802001, 0x00002081, 0x00002081, 0x00000080,
           0x00802081, 0x00000081, 0x00000001, 0x00002000,
           0x00800001, 0x00002001, 0x00802080, 0x00800081,
           0x00002001, 0x00002080, 0x00800000, 0x00802001,
           0x00000080, 0x00800000, 0x00002000, 0x00802080
          ]

    SP5 = [
           0x00000100, 0x02080100, 0x02080000, 0x42000100,
           0x00080000, 0x00000100, 0x40000000, 0x02080000,
           0x40080100, 0x00080000, 0x02000100, 0x40080100,
           0x42000100, 0x42080000, 0x00080100, 0x40000000,
           0x02000000, 0x40080000, 0x40080000, 0x00000000,
           0x40000100, 0x42080100, 0x42080100, 0x02000100,
           0x42080000, 0x40000100, 0x00000000, 0x42000000,
           0x02080100, 0x02000000, 0x42000000, 0x00080100,
           0x00080000, 0x42000100, 0x00000100, 0x02000000,
           0x40000000, 0x02080000, 0x42000100, 0x40080100,
           0x02000100, 0x40000000, 0x42080000, 0x02080100,
           0x40080100, 0x00000100, 0x02000000, 0x42080000,
           0x42080100, 0x00080100, 0x42000000, 0x42080100,
           0x02080000, 0x00000000, 0x40080000, 0x42000000,
           0x00080100, 0x02000100, 0x40000100, 0x00080000,
           0x00000000, 0x40080000, 0x02080100, 0x40000100
          ]

    SP6 = [
           0x20000010, 0x20400000, 0x00004000, 0x20404010,
           0x20400000, 0x00000010, 0x20404010, 0x00400000,
           0x20004000, 0x00404010, 0x00400000, 0x20000010,
           0x00400010, 0x20004000, 0x20000000, 0x00004010,
           0x00000000, 0x00400010, 0x20004010, 0x00004000,
           0x00404000, 0x20004010, 0x00000010, 0x20400010,
           0x20400010, 0x00000000, 0x00404010, 0x20404000,
           0x00004010, 0x00404000, 0x20404000, 0x20000000,
           0x20004000, 0x00000010, 0x20400010, 0x00404000,
           0x20404010, 0x00400000, 0x00004010, 0x20000010,
           0x00400000, 0x20004000, 0x20000000, 0x00004010,
           0x20000010, 0x20404010, 0x00404000, 0x20400000,
           0x00404010, 0x20404000, 0x00000000, 0x20400010,
           0x00000010, 0x00004000, 0x20400000, 0x00404010,
           0x00004000, 0x00400010, 0x20004010, 0x00000000,
           0x20404000, 0x20000000, 0x00400010, 0x20004010
          ]

    SP7 = [
           0x00200000, 0x04200002, 0x04000802, 0x00000000,
           0x00000800, 0x04000802, 0x00200802, 0x04200800,
           0x04200802, 0x00200000, 0x00000000, 0x04000002,
           0x00000002, 0x04000000, 0x04200002, 0x00000802,
           0x04000800, 0x00200802, 0x00200002, 0x04000800,
           0x04000002, 0x04200000, 0x04200800, 0x00200002,
           0x04200000, 0x00000800, 0x00000802, 0x04200802,
           0x00200800, 0x00000002, 0x04000000, 0x00200800,
           0x04000000, 0x00200800, 0x00200000, 0x04000802,
           0x04000802, 0x04200002, 0x04200002, 0x00000002,
           0x00200002, 0x04000000, 0x04000800, 0x00200000,
           0x04200800, 0x00000802, 0x00200802, 0x04200800,
           0x00000802, 0x04000002, 0x04200802, 0x04200000,
           0x00200800, 0x00000000, 0x00000002, 0x04200802,
           0x00000000, 0x00200802, 0x04200000, 0x00000800,
           0x04000002, 0x04000800, 0x00000800, 0x00200002
          ]

    SP8 = [
           0x10001040, 0x00001000, 0x00040000, 0x10041040,
           0x10000000, 0x10001040, 0x00000040, 0x10000000,
           0x00040040, 0x10040000, 0x10041040, 0x00041000,
           0x10041000, 0x00041040, 0x00001000, 0x00000040,
           0x10040000, 0x10000040, 0x10001000, 0x00001040,
           0x00041000, 0x00040040, 0x10040040, 0x10041000,
           0x00001040, 0x00000000, 0x00000000, 0x10040040,
           0x10000040, 0x10001000, 0x00041040, 0x00040000,
           0x00041040, 0x00040000, 0x10041000, 0x00001000,
           0x00000040, 0x10040040, 0x00001000, 0x00041040,
           0x10001000, 0x00000040, 0x10000040, 0x10040000,
           0x10040040, 0x10000000, 0x00040000, 0x10001040,
           0x00000000, 0x10041040, 0x00040040, 0x10000040,
           0x10040000, 0x10001000, 0x10001040, 0x00000000,
           0x10041040, 0x00041000, 0x00041000, 0x00001040,
           0x00001040, 0x00040040, 0x10000000, 0x10041000
          ]

    def desfunc block, keys
      leftt = block[0]
      right = block[1]

      work = ((leftt >> 4) ^ right) & 0x0f0f0f0f
      right ^= work
      leftt ^= (work << 4)
      work = ((leftt >> 16) ^ right) & 0x0000ffff
      right ^= work
      leftt ^= (work << 16)
      work = ((right >> 2) ^ leftt) & 0x33333333
      leftt ^= work
      right ^= (work << 2)
      work = ((right >> 8) ^ leftt) & 0x00ff00ff
      leftt ^= work
      right ^= (work << 8)
      right = ((right << 1) | ((right >> 31) & 1)) & 0xffffffff
      work = (leftt ^ right) & 0xaaaaaaaa
      leftt ^= work
      right ^= work
      leftt = ((leftt << 1) | ((leftt >> 31) & 1)) & 0xffffffff

      8.times do |i|
        work  = (right << 28) | (right >> 4)
        work ^= keys[i * 4 + 0]
        fval  = SP7[ work		 & 0x3f]
        fval |= SP5[(work >>  8) & 0x3f]
        fval |= SP3[(work >> 16) & 0x3f]
        fval |= SP1[(work >> 24) & 0x3f]
        work  = right ^ keys[i * 4 + 1]
        fval |= SP8[ work		 & 0x3f]
        fval |= SP6[(work >>  8) & 0x3f]
        fval |= SP4[(work >> 16) & 0x3f]
        fval |= SP2[(work >> 24) & 0x3f]
        leftt ^= fval
        work  = (leftt << 28) | (leftt >> 4)
        work ^= keys[i * 4 + 2]
        fval  = SP7[ work		 & 0x3f]
        fval |= SP5[(work >>  8) & 0x3f]
        fval |= SP3[(work >> 16) & 0x3f]
        fval |= SP1[(work >> 24) & 0x3f]
        work  = leftt ^ keys[i * 4 + 3]
        fval |= SP8[ work		 & 0x3f]
        fval |= SP6[(work >>  8) & 0x3f]
        fval |= SP4[(work >> 16) & 0x3f]
        fval |= SP2[(work >> 24) & 0x3f]
        right ^= fval
      end

      right = ((right << 31) | (right >> 1)) & 0xffffffff
      work = (leftt ^ right) & 0xaaaaaaaa
      leftt ^= work
      right ^= work
      leftt = ((leftt << 31) | (leftt >> 1)) & 0xffffffff
      work = ((leftt >> 8) ^ right) & 0x00ff00ff
      right ^= work
      leftt ^= (work << 8)
      work = ((leftt >> 2) ^ right) & 0x33333333
      right ^= work
      leftt ^= (work << 2)
      work = ((right >> 16) ^ leftt) & 0x0000ffff
      leftt ^= work
      right ^= (work << 16)
      work = ((right >> 4) ^ leftt) & 0x0f0f0f0f
      leftt ^= work
      right ^= (work << 4)

      [right, leftt]
    end
  end

end

end
