require 'securerandom'

require './aes_cbc'
require './aes_ecb'
require './bytes'

module Crypto
  AES_ECB = ::AES_ECB
  AES_CBC = ::AES_CBC

  # Return msg XORed with a repeating key.
  def self.vigenere(key, msg)
    key = Bytes.new(key) unless key.is_a?(Bytes) 
    msg = Bytes.new(msg) unless msg.is_a?(Bytes) 

    repkey = key.cycle((msg.length / key.length.to_f).ceil)
    xormsg = msg.zip(repkey).map! { |a, b| a ^ b }

    Bytes.new(xormsg)
  end

  # Return a new message padded to a fixed-sized block.
  def self.pkcs7_padding(msg, blocksz = 16)
    ret = msg.clone
    ret = Bytes.new(ret) unless ret.is_a?(Bytes)

    pad_num = blocksz - ret.length % blocksz
    pad_num.times { ret << pad_num }

    ret
  end

  # Return a msg encrypted with a random key, that may use ECB or CBC mode.
  def self.encryption_mode_oracle(msg)
    msg = Bytes.new(msg) unless msg.is_a?(Bytes)
    key = Bytes.new(SecureRandom.random_bytes(16))

    # Prepend and append 5-10 random bytes (count chosen randomly).
    (rand(6)+5).times { msg.insert(0, rand(256)) }
    (rand(6)+5).times { msg.push(rand(256)) }

    # Randomly choose a block cipher mode.
    if rand(2).zero?
      puts "Hint: ECB"
      cipher = AES_ECB.new(key)
      cipher.encrypt(msg)
    else
      puts "Hint: CBC"
      cipher = AES_CBC.new(key, SecureRandom.random_bytes(16))
      # Do not return IV, though realistically CBC should return one.
      cipher.encrypt(msg)[1]
    end
  end
end
