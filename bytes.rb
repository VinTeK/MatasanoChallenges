require 'base64'

# An Array of byte-sized integers.
class Bytes < Array
  def initialize(data = [], encoding = :ascii)
    if data.is_a?(String)
      if encoding == :hex
        data = [data].pack('H*')
      elsif encoding == :base64
        data = Base64.strict_decode64(data)
      end

      # Unpack into an Array of bytes.
      super(data.unpack('C*'))
    elsif data.is_a?(Array)
      unless data.all? { |x| x.is_a?(Fixnum) && (0..255) === x }
        fail TypeError, "data elements must be byte-sized integers"
      end

      # Use argument Array as data.
      super(data)
    else
      fail ArgumentError, "data must be a String or Array"
    end
  end

  def ^(other)
    ret = self.zip(other).delete_if { |b1, b2| b1.nil? or b2.nil? }
    Bytes.new(ret.map! { |b1, b2| b1 ^ b2 })
  end

  def ascii
    self.pack('C*')
  end

  def hex
    ret = self.map { |b| b.to_s(16) }.join
    (ret.length % 2 == 0) ? ret : '0' << ret
  end

  def base64
    Base64.strict_encode64(self.pack('C*')).chomp
  end
end
