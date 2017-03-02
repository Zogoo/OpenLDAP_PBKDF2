#!/usr/bin/env ruby

require 'openssl'
require 'base64'
require 'securerandom'
require 'byebug'

ITERATION = 60_000
LENGTH = 20
SALT_LENGTH = 16

TEST_PWD = 'password'.freeze

def pbkdf2_base64(b)
  # Note! PBKDF2 uses a non-standard alphabet with base64
  Base64.strict_encode64(b).tr('=', '').tr('+', '.')
end

def new_salt(cb)
  salt = SecureRandom.base64(cb).tr('=', '')
end

def pbkdf2(passwd, salt)
  # salty = Base64.decode64(salt)
  key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(passwd, salt, ITERATION, LENGTH)
  pbkdf2_base64(key)
end

def pbkdf2_ldap(pwd)
  salt = new_salt(SALT_LENGTH)
  key_spec = pbkdf2(pwd, salt)
  encoded = "{PBKDF2}#{ITERATION}$#{salt}$#{key_spec}"
  encoded
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
print pbkdf2(TEST_PWD, salt)
print "\n"

# Test 2
print "*******Constanst salt test******\n"
print "Java application generates below when pw: password, salt: Test \n"
print "Should be same as:\nrNhUHYX19u.6A47Oe.abiCXD9Zc\n"
print "Ruby application generates below:\n"
print pbkdf2(TEST_PWD, 'Test')
print "\n"
