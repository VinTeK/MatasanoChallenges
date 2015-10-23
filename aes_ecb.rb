require 'openssl'

require './bytes'

class AES_ECB
  KEY_SZ    = [16, 24, 32]
  BLOCK_SZ  = 16

  def initialize(key)
    key = Bytes.new(key) unless key.is_a?(Bytes)

    unless KEY_SZ.include?(key.length)
      fail ArgumentError, 'key size must be 16, 24, or 32 bytes'
    end

    @key    = key
    @cipher = OpenSSL::Cipher.new("AES#{key.length*8}")
  end

  # Return the ciphertext of an unencrypted plaintext.
  def encrypt(msg)
    msg = Bytes.new(msg) unless msg.is_a?(Bytes)

    # Encrypt message block by block.
    ctext = []
    (0..msg.length/BLOCK_SZ).each do |block_i|
      # Setup OpenSSL cipher mode. This is done on each iteration so that we
      # are reusing the EXACT same AES instance for each block encryption.
      # Obviously this demonstrates why ECB is not CPA-secure.
      @cipher.encrypt
      @cipher.padding = 0
      @cipher.key = @key.ascii

      block = msg.slice(block_i*BLOCK_SZ, BLOCK_SZ)
      block = Crypto.pkcs7_padding(block) unless block.length == BLOCK_SZ

      enc = Bytes.new(@cipher.update(block.ascii) + @cipher.final)
      ctext << enc
    end

    ctext.reduce(:concat)
  end

  # Return the plaintext of an encrypted message.
  def decrypt(msg)
    msg = Bytes.new(msg) unless msg.is_a?(Bytes)

    ptext = []
    (0..msg.length/BLOCK_SZ - 1).each do |block_i|
      @cipher.decrypt
      @cipher.padding = 0
      @cipher.key = @key.ascii

      block = msg.slice(block_i*BLOCK_SZ, BLOCK_SZ)

      dec = Bytes.new(@cipher.update(block.ascii) + @cipher.final)
      ptext << dec
    end

    ptext = ptext.reduce(:concat)

    # Strip off padding.
    Bytes.new(ptext.reject { |b| b == ptext[-1] })
  end
end
