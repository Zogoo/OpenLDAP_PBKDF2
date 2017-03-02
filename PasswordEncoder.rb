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

def pbkdf2_base64(b)
  # Note! PBKDF2 uses a non-standard alphabet with base64
  Base64.strict_encode64(b).tr('=', '').tr('+', '.')
end

def new_salt(cb)
  SecureRandom.base64(cb).tr('=', '')
end

def pbkdf2(passwd, salt)
  key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(passwd, salt, ITERATION, LENGTH)
  # key.unpack('h*').first
end

def pbkdf2_ldap(pwd)
  salt = new_salt(SALT_LENGTH)
  key_spec = pbkdf2(pwd, salt)
  encoded = "{PBKDF2}#{ITERATION}$#{salt}$#{pbkdf2_base64(key_spec)}"
  encoded
end

print "\n LDAP PASS:"
print pbkdf2_ldap(TEST_PWD)
print "\n"

byebug
