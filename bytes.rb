require 'base64'

class Bytes
  include Enumerable

  def initialize(data, encoding = :ascii)
    if data.is_a?(String)
      if encoding == :hex
        data = [data].pack('H*')
      elsif encoding == :base64
        data = Base64.strict_decode64(data)
      end

      # Unpack into an array of bytes.
      @bytes = data.unpack('C*')
    elsif data.is_a?(Array)
      unless data.all? { |x| x.is_a?(Fixnum) && (0..255) === x }
          fail TypeError, "data elements must be byte-sized integers"
      end

      # Directly use argument as an Array of bytes.
      @bytes = data
    else
      fail ArgumentError, "data must be a String or Array"
    end
  end

  def each
    if block_given?
      @bytes.each { |b| yield b }
    else
      self.to_enum
    end
  end

  def clone
    Bytes.new(@bytes.clone)
  end

  def ==(other)
    self.class == other.class && self.bytes == other.bytes
  end

  def <<(data)
    if data.is_a?(Fixnum) && (0..255) === data
      @bytes.push(data)
    elsif data.is_a?(Array) &&
          data.all? { |x| x.is_a?(Fixnum) && (0..255) === x }
      @bytes.concat(data)
    else
      fail TypeError, "data elements must be byte-sized integers"
    end
  end

	def ^(other)
		ret = self.zip(other).delete_if { |b1, b2| b1.nil? or b2.nil? }
		Bytes.new(ret.map! { |b1, b2| b1 ^ b2 })
	end

	def [](index)
    if index.is_a?(Range)
		  Bytes.new(@bytes[index])
    else
		  Bytes.new([@bytes[index]])
    end
	end

  def slice(index, length = 1)
    if index.is_a?(Range)
      self[index]
    else
      self[index..index+length-1]
    end
  end

	def ascii
		@bytes.pack('C*')
	end

	def hex
		ret = @bytes.map { |b| b.to_s(16) }.join
    (ret.length % 2 == 0) ? ret : '0' << ret
	end

	def base64
		Base64.strict_encode64(@bytes.pack('C*')).chomp
	end

	def length
		@bytes.length
	end

	def to_s
		self.base64
	end

	attr_reader :bytes

	protected
	attr_writer :bytes
end
