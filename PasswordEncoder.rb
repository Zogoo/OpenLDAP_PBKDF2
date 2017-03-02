#!/usr/bin/env ruby

require 'openssl'
require 'base64'
require 'securerandom'
require 'byebug'

ITERATION = 60_000
LENGTH = 20
SALT_LENGTH = 16

TEST_PWD = 'password'.freeze

# RFC4648 Character encoding
def pbkdf2_base64(b)
  # Note! PBKDF2 uses a non-standard alphabet with base64
  Base64.strict_encode64(b).tr('=', '').tr('+', '.')
end

# RFC4648 will come out from SecureRandom
# Hence decoding to ISO-8859-1 characters
def new_salt(cb)
  salt = SecureRandom.base64(cb).tr('=', '')
  Base64.decode64(salt)
end

# Password-Based Key Derivation Function
# Pseudorandom function is HMAC-SHA1
def pbkdf2(passwd, salt, iteration = nil, len = nil)
  iteration = iteration.nil? ? ITERATION : iteration
  len = len.nil? ? LENGTH : len
  OpenSSL::PKCS5.pbkdf2_hmac_sha1(passwd, salt, iteration, len)
end

# Generate LDAP based hash key
def pbkdf2_ldap(pwd)
  salt = new_salt(SALT_LENGTH)
  key_spec = pbkdf2(pwd, salt)
  encoded = "{PBKDF2}#{ITERATION}$#{pbkdf2_base64(salt)}$#{pbkdf2_base64(key_spec)}"
  encoded
end

# LDAP password parser
def decrypt_pbdf2_ldap(string)
  pw_info = string.gsub('$')
  iteration = pw_info[0].gsub('{PBKDF2}')[1]
  encoded_salt = pw_info[1]
  salt = Base64.decode64(encoded_salt)
  hashed_password = pw_info[2]
  { i: iteration, s: salt, h: hashed_password }
end

# Validate your password
def validate_password(ldap_str, password)
  pw = decrypt_pbdf2_ldap(ldap_str)
  pbkdf2(password, pw { :s }, pw { :i })
end

# Printing
print "\n LDAP PASS:\n#{pbkdf2_ldap(TEST_PWD)}\n"

# Test 1
print "*******Dynamic salt test******\n"
print "Java application generate belows when \n"
print "pw: password\n"
print "And LDAP hashed: {PBKDF2}60000$REJsu8X8xHHAf0m0f7BVjw$G0IsVTZ6HOTxQWqbZ9xzalNlQJI\n"
print "Should be same as:\nG0IsVTZ6HOTxQWqbZ9xzalNlQJI\n"
print "Ruby application generates below:\n"
salt = Base64.decode64('REJsu8X8xHHAf0m0f7BVjw')
print pbkdf2_base64(pbkdf2(TEST_PWD, salt))
print "\n"

# Test 2
print "*******Constanst salt test******\n"
print "Java application generates below when pw: password, salt: Test \n"
print "Should be same as:\nrNhUHYX19u.6A47Oe.abiCXD9Zc\n"
print "Ruby application generates below:\n"
print pbkdf2_base64(pbkdf2(TEST_PWD, 'Test'))
print "\n"
