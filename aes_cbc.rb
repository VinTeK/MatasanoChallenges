require 'openssl'

require './bytes'

# NB: Due to the nature of CBC and its changing internal IV state, you CANNOT 
# reuse the same AES_CBC class for encrypting/decrypting DIFFERENT messages.
class AES_CBC
  KEY_SZ    = [16, 24, 32]
  BLOCK_SZ  = 16

  def initialize(key, iv = Bytes.new(Array.new(BLOCK_SZ, 0)))
    key = Bytes.new(key) unless key.is_a?(Bytes)

    unless KEY_SZ.include?(key.length)
      fail ArgumentError, 'key size must be 16, 24, or 32 bytes'
    end

    @key    = key
    @state  = iv # CHANGES FROM BLOCK TO BLOCK--internal IV state.
    @cipher = OpenSSL::Cipher.new("AES-#{key.length*8}-ECB")
  end

  # Return an [IV, ciphertext] pair for a message.
  def encrypt(msg)
    msg = Bytes.new(msg) unless msg.is_a?(Bytes)

    # Capture the IV for this message.
    iv = @state

    # Setup OpenSSL cipher mode.
    @cipher.encrypt
    @cipher.padding = 0
    @cipher.key = @key.ascii

    # Encrypt message block by block.
    ctext = []
    (0..msg.length/BLOCK_SZ).each do |block_i|
      block = msg.slice(block_i*BLOCK_SZ, BLOCK_SZ)
      block = Crypto.pkcs7_padding(block) unless block.length == BLOCK_SZ

      block ^= @state
      enc = Bytes.new(@cipher.update(block.ascii) + @cipher.final)
      ctext << enc

      @state = enc
    end

    [iv, ctext.reduce(:concat)]
  end

  # Return the plaintext of an encrypted message.
  def decrypt(msg)
    msg = Bytes.new(msg) unless msg.is_a?(Bytes)

    @cipher.decrypt
    @cipher.padding = 0
    @cipher.key = @key.ascii

    ptext = []
    (0..msg.length/BLOCK_SZ - 1).each do |block_i|
      block = msg.slice(block_i*BLOCK_SZ, BLOCK_SZ)

      dec = Bytes.new(@cipher.update(block.ascii) + @cipher.final)
      dec ^= @state
      ptext << dec

      @state = block
    end

    ptext = ptext.reduce(:concat)

    # Strip off padding.
    Bytes.new(ptext.reject { |b| b == ptext[-1] })
  end
end
