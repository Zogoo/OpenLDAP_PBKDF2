#!/usr/bin/env ruby

require 'json'
require 'openssl'
require 'base64'
require 'gibberish'
require 'excon'
require 'securerandom'
require 'optparse'
require 'byebug'

ITERATION = 60_000
LENGTH = 20
SALT_LENGTH = 16

TEST_PWD = '\u20ACuro'.freeze

def bin2hex(str)
  str.unpack('C*').map{ |b| "%02X" % b }.join('')
end

def bin2hex(str)
  str.unpack('C*').map{ |b| "%c" % b }.join('')
end

def hex2bin(str)
  [str].pack "H*"
end

def pbkdf2_base64(b)
  # Note! PBKDF2 uses a non-standard alphabet with base64
  Base64.strict_encode64(b).tr('=', '').tr('+', '.')
end

def newSalt(cb)
  SecureRandom.base64(cb).tr('=', '')
end

def pbkdf2(passwd, salt)
  key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(passwd, salt, ITERATION, LENGTH)
  key.unpack('c*')
  byebug
end

def pbkdf2_ldap(pwd)
  salt = newSalt(SALT_LENGTH)
  key_spec = pbkdf2(pwd, salt)
  encoded = "{PBKDF2}#{ITERATION}$#{salt}$#{key_spec}"
  encoded
end

print "\n LDAP PASS:"
print pbkdf2_ldap(TEST_PWD)
print "\n"
