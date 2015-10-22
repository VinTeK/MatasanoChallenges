require './bytes'

module Cryptanalysis
  # Return a Hash of characters and their number of occurrences.
  def self.map_occurrences(str)
    ret = {}
    str.each_char do |c|
      # Only map alphanumeric and space chars.
      next unless c.match(/^[[:alnum:][:space:]]$/)

      ret[c] ? ret[c] += 1 : ret[c] = 1
    end
    ret
  end

  # Return the probability that str is valid English.
  def self.prob_english(str)
    magic = ' etaoinshrdlu'

    # Get the most frequent chars in str. 
    top = map_occurrences(str).sort { |a, b| b[1] <=> a[1] }.take(magic.size)
    topchars = top.map! { |x| x[0] }.join

    # Score based on how many chars show up in our magic string.
    topchars.count(magic) / magic.length.to_f
  end

  # Return the bit-wise hamming distance between two Bytes.
  def self.hamming_dist(a, b)
    a = Bytes.new(a) unless a.is_a?(Bytes)
    b = Bytes.new(b) unless b.is_a?(Bytes)

    unless a.length == b.length
      fail ArgumentError, "arguments must be equal length"
    end

    a.zip(b).map! { |x, y| (x ^ y).to_s(2).count('1') }.reduce(:+)
  end

  # Return the top five likeliest key sizes based on normalized edit distance.
  # Useful for detecting key size in Vigenere cipher.
  def self.keysz_guesses(msg)
    msg = Bytes.new(msg) unless msg.is_a?(Bytes)

    distances = {}

    # Iterate through potential key sizes.
    (2..40).each do |keysz|
      num_blocks = msg.length / keysz
      mean = 0

      # Calculate the mean of the hamming dists for each key-sized block.
      (0..num_blocks-2).each do |block_i|
        b1 = msg.slice(block_i*keysz, keysz)
        b2 = msg.slice(block_i*keysz+keysz, keysz)

        mean += hamming_dist(b1, b2)
      end

      # Normalize mean.
      mean /= num_blocks * keysz.to_f
      distances[keysz] = mean
    end

    distances.keep_if { |k, v| not v.nan? }
    distances.sort { |a, b| a[1] <=> b[1] }.take(5)
  end

  # Return true if there are repeated blocks in a message, indicating ECB mode.
  # NOTE: assumes that msg[0] is the very beginning of the message.
  def self.is_ecb?(msg, blocksz = 16)
    msg = Bytes.new(msg) unless msg.is_a?(Bytes)

    xss = []
    (0..msg.length).step(blocksz).each { |i| xss.push(msg.slice(i, blocksz)) } 

    xss.find { |xs| xss.count(xs) > 1 } != nil
  end
end
