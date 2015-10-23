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
end
