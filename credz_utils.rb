#!/usr/bin/env ruby

require 'debug_utils'
require 'password_utils'
require 'sqlite3'
require 'optparse'
require 'ffi'
require 'json'

$debug = false




module Credentials

## # PK11SlotInfo
##     /* the PKCS11 function list for this slot */
##     void *functionList;
##     SECMODModule *module; /* our parent module */
##     /* Boolean to indicate the current state of this slot */
##     PRBool needTest;	/* Has this slot been tested for Export complience */
##     PRBool isPerm;	/* is this slot a permanment device */
##     PRBool isHW;	/* is this slot a hardware device */
##     PRBool isInternal;  /* is this slot one of our internal PKCS #11 devices */
##     PRBool disabled;	/* is this slot disabled... */
##     PK11DisableReasons reason; 	/* Why this slot is disabled */
##     PRBool readOnly;	/* is the token in this slot read-only */
##     PRBool needLogin;	/* does the token of the type that needs 
## 			 * authentication (still true even if token is logged 
## 			 * in) */
##     PRBool hasRandom;   /* can this token generated random numbers */
##     PRBool defRWSession; /* is the default session RW (we open our default 
## 			  * session rw if the token can only handle one session
## 			  * at a time. */
##     PRBool isThreadSafe; /* copied from the module */
##     /* The actual flags (many of which are distilled into the above PRBools) */
##     CK_FLAGS flags;      /* flags from PKCS #11 token Info */
##     /* a default session handle to do quick and dirty functions */
##     CK_SESSION_HANDLE session; 
##     PZLock *sessionLock; /* lock for this session */
##     /* our ID */
##     CK_SLOT_ID slotID;
##     /* persistant flags saved from startup to startup */
##     unsigned long defaultFlags;
##     /* keep track of who is using us so we don't accidently get freed while
##      * still in use */
##     PRInt32 refCount;    /* to be in/decremented by atomic calls ONLY! */
##     PZLock *freeListLock;
##     PK11SymKey *freeSymKeysWithSessionHead;
##     PK11SymKey *freeSymKeysHead;
##     int keyCount;
##     int maxKeyCount;
##     /* Password control functions for this slot. many of these are only
##      * active if the appropriate flag is on in defaultFlags */
##     int askpw;		/* what our password options are */
##     int timeout;	/* If we're ask_timeout, what is our timeout time is 
## 			 * seconds */
##     int authTransact;   /* allow multiple authentications off one password if
## 		         * they are all part of the same transaction */
##     PRTime authTime;	/* when were we last authenticated */
##     int minPassword;	/* smallest legal password */
##     int maxPassword;	/* largest legal password */
##     PRUint16 series;	/* break up the slot info into various groups of
## 			 * inserted tokens so that keys and certs can be
## 			 * invalidated */
##     PRUint16 flagSeries;/* record the last series for the last event
##                          * returned for this slot */
##     PRBool flagState;	/* record the state of the last event returned for this
## 			 * slot. */
##     PRUint16 wrapKey;	/* current wrapping key for SSL master secrets */
##     CK_MECHANISM_TYPE wrapMechanism;
## 			/* current wrapping mechanism for current wrapKey */
##     CK_OBJECT_HANDLE refKeys[1]; /* array of existing wrapping keys for */
##     CK_MECHANISM_TYPE *mechanismList; /* list of mechanism supported by this
## 				       * token */
##     int mechanismCount;
##     /* cache the certificates stored on the token of this slot */
##     CERTCertificate **cert_array;
##     int array_size;
##     int cert_count;
##     char serial[16];
##     /* since these are odd sizes, keep them last. They are odd sizes to 
##      * allow them to become null terminated strings */
##     char slot_name[65];
##     char token_name[33];
##     PRBool hasRootCerts;
##     PRBool hasRootTrust;
##     PRBool hasRSAInfo;
##     CK_FLAGS RSAInfoFlags;
##     PRBool protectedAuthPath;
##     PRBool isActiveCard;
##     PRIntervalTime lastLoginCheck;
##     unsigned int lastState;
##     /* for Stan */
##     NSSToken *nssToken;
##     /* fast mechanism lookup */
##     char mechanismBits[256];
## };



module NSS
  extend FFI::Library
  ffi_lib 'nss3'

  enum :secStatus, [
                    :secWouldBlock, -2,
                    :secFailure,
                    :secSuccess
                   ]

  enum :secItemType, [
                      :siBuffer, 0,
                      :siClearDataBuffer,
                      :siCipherDataBuffer,
                      :siDERCertBuffer,
                      :siEncodedCertBuffer,
                      :siDERNameBuffer,
                      :siEncodedNameBuffer,
                      :siAsciiNameString,
                      :siAsciiString,
                      :siDEROID,
                      :siUnsignedInteger,
                      :siUTCTime,
                      :siGeneralizedTime,
                      :siVisibleString,
                      :siUTF8String,
                      :siBMPString
                     ]

  class SECItem < FFI::Struct
    layout :type, :secItemType,
           :data, :pointer,
           :len,  :int
  end

  attach_function :NSS_Init, [ :string ], :int
  attach_function :PK11_GetInternalKeySlot, [ ], :pointer
  attach_function :PK11_CheckUserPassword, [ :pointer , :string ], :secStatus
  attach_function :PK11_Authenticate, [ :pointer, :int, :pointer ], :int
  attach_function :PK11SDR_Decrypt, [ :pointer, :pointer, :pointer ], :int
end

module Decrypt

class Default

  def parse(input, type)
    if type == :file
      parse_file(input)
    elsif type == :string
      parse_string(input)
    end
  end

  def parse_file(input)
  end

  def parse_string(input)
  end

end

class UVNC < Default

  def parse_file(input)
    f = open(input, 'r')
    f.readlines.each do |line|
      if line.start_with? "passwd"
        parse_string(line.strip.split("=")[1][0..15])
      end
    end
  end

  def parse_string(input)
    print_info "#{Password::VNC.decrypt(input.unhex)} (#{input})"
  end

end

# Good read => http://www.infond.fr/2010/04/firefox-passwords-management-leaks.html
class Firefox

  def decrypt(source, hostname, encryptedUsername, encryptedPassword)

    enc_username = NSS::SECItem.new
    enc_password = NSS::SECItem.new
    dec_username = NSS::SECItem.new
    dec_password = NSS::SECItem.new

    enc_username[:data] = FFI::MemoryPointer.from_string(encryptedUsername.base64_decode)
    enc_username[:len]  = encryptedUsername.base64_decode.length

    enc_password[:data] = FFI::MemoryPointer.from_string(encryptedPassword.base64_decode)
    enc_password[:len]  = encryptedPassword.base64_decode.length

    if NSS.PK11SDR_Decrypt(enc_username, dec_username, nil) == -1
      print_debug "PK11SDR_Decrypt failed for username"
    end

    if NSS.PK11SDR_Decrypt(enc_password, dec_password, nil) == -1
      print_debug "PK11SDR_Decrypt failed for password"
    end

    username = dec_username[:data].read_string()[0..dec_username[:len] -1]
    password = dec_password[:data].read_string()[0..dec_password[:len] -1]
    print_info "#{source} => #{hostname} -- #{username} -- #{password}"

  end

  def parse(input, type)
    unless type == :dir
      print_error "#{input} type (#{type}) is not 'dir'"
    end

    unless NSS.NSS_Init(input) == 0
      print_debug "Failed at reading #{input}"
      return
    end

    keySlot = NSS.PK11_GetInternalKeySlot()
    NSS.PK11_CheckUserPassword(keySlot, "")
    NSS.PK11_Authenticate(keySlot, 1, nil)

    db_path = "#{input}/signons.sqlite"
    if File.exists? db_path

      print_debug "#{input}/signons.sqlite exists"
      db = SQLite3::Database.new( db_path )
      ff_credz = db.execute("SELECT hostname, encryptedUsername, encryptedPassword FROM moz_logins")
      ff_credz.each do |hostname, encryptedUsername, encryptedPassword|
        self.decrypt(db_path, hostname, encryptedUsername, encryptedPassword)
      end
      db.close

    end

    db_path = "#{input}/logins.json"
    if File.exists? db_path

      print_debug "#{input}/logins.json exists"
      db = File.open( db_path )
      json = JSON.parse( db.read )

      json["logins"].each do |login|
        self.decrypt(db_path, login["hostname"], login["encryptedUsername"], login["encryptedPassword"])
      end

    end

  end

end

end

end

if $0 == __FILE__

  options = {
    :input => [],
  }

  opts = OptionParser.new
  opts.banner = "Usage: #{$0} -f <format> -t <input-type> -i <input> [options]"

  opts.on("-f", "--format FORMAT", "The format to be read") do |f|
    case f.downcase
    when "uvnc"
      options[:format] = Credentials::Decrypt::UVNC
    when "ultravnc"
      options[:format] = Credentials::Decrypt::UVNC
    when "ff"
      options[:format] = Credentials::Decrypt::Firefox
    when "firefox"
      options[:format] = Credentials::Decrypt::Firefox
    else
      print_error "Unknown format #{f}"
      puts opts.banner
      exit
    end
  end

  opts.on("-i", "--input INPUT", "The input would usually be some string(s) of file(s)") do |i|
    options[:input] << i
  end

  opts.on("-t", "--type TYPE", "Specify if input will be string(s) or file(s)") do |t|
    case t.downcase
    when "string"
      options[:type] = :string
    when "file"
      options[:type] = :file
    when "dir"
      options[:type] = :dir
    else
      print_error "Unknown type #{t}"
      puts opts.banner
      exit
    end
  end

  opts.on("-o", "--output OUTPUT", "The sqlite3 file you want to put the credz on") do |o|
    options[:output] = o
  end

  opts.on("-d", "--debug") do
    $debug = true
  end

  opts.parse!

  parser = options[:format].new()
  options[:input].each do |input|
    puts "Processing #{input}"
    parser.parse(input, options[:type])
  end

end
