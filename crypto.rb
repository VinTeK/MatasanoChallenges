require './bytes'

module Crypto
  # Return msg XORed with a repeating key.
  def self.vigenere(key, msg)
    key = Bytes.new(key) unless key.is_a?(Bytes) 
    msg = Bytes.new(msg) unless msg.is_a?(Bytes) 

    repkey = key.cycle((msg.length / key.length.to_f).ceil)
    xormsg = msg.zip(repkey).map! { |a, b| a ^ b }

    Bytes.new(xormsg)
  end
end
