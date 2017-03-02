#!/usr/bin/env ruby

require 'json'
require 'openssl'
require 'base64'
require 'gibberish'
require 'excon'
require 'securerandom'
require 'optparse'
require 'byebug'
require 'pbkdf2'

ITERATION = 60_000
LENGTH = 20
SALT_LENGTH = 16

TEST_PWD = '\u20ACuro'.freeze

def bin2hex(str)
  str.unpack('C*').map{ |b| "%02X" % b }.join('')
end

def hex2bin(str)
  [str].pack "H*"
end

def pbkdf2_base64(b)
  # Note! PBKDF2 uses a non-standard alphabet with base64
  hex = bin2hex(b)
  hex_enc = Base64.strict_encode64(hex).tr('=', '')
end

def newSalt(cb)
  hex2bin(SecureRandom.base64(cb).tr('=', ''))
end

def encrypt(pwd, salt = nil)
  cipher = OpenSSL::Cipher::Cipher.new('AES-256-CBC')
  cipher.encrypt
  if salt.nil?
    salt = OpenSSL::Random.random_bytes(8)
  else
    salt = hex2bin(salt)
  end
  iv = cipher.random_iv
  key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(pwd, salt, ITERATION, LENGTH * 8)
  cipher.key = key
  iv = cipher.random_iv
  cipher.iv = iv
  cipher.padding = 0
  encrypted_binary = cipher.update('') + cipher.final

  return bin2hex(salt), bin2hex(iv), bin2hex(encrypted_binary)
end

def pbkdf2_ldap(pwd)
  salt = newSalt(SALT_LENGTH)
  key_spec = encrypt(pwd, salt)
  encoded = "{PBKDF2}#{ITERATION}$#{pbkdf2_base64(salt)}$#{pbkdf2_base64(key_spec)}"
  byebug
  encoded
end

print "\n LDAP PASS:"
# print pbkdf2_ldap(TEST_PWD)
salty = newSalt(SALT_LENGTH)
# aa = PBKDF2.new(:password=>TEST_PWD, :salt=> salty, :iterations=>ITERATION)
bb = OpenSSL::PKCS5.pbkdf2_hmac_sha1(TEST_PWD, salty, ITERATION, LENGTH * 8)
byebug
print "\n"
