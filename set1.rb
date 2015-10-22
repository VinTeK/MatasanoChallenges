require 'io/console'
require 'openssl'

require './crypto'
require './cryptanalysis'

DO_RUN = [
  #:chal1,
  #:chal2,
  #:chal3,
  #:chal4,
  #:chal5,
  #:chal6,
  #:chal7,
  #:chal8
]

if DO_RUN.include?(:chal1)
  puts '================Challenge 1:================'

  b1 = Bytes.new("49276d206b696c6c696e6720796f7572"\
                 "20627261696e206c696b65206120706f"\
                 "69736f6e6f7573206d757368726f6f6d", :hex)

  puts b1.base64
end

if DO_RUN.include?(:chal2)
  puts '================Challenge 2:================'

  b21 = Bytes.new("1c0111001f010100061a024b53535009181c", :hex)
  b22 = Bytes.new("686974207468652062756c6c277320657965", :hex)

  puts (b21 ^ b22).hex
end

if DO_RUN.include?(:chal3)
  puts '================Challenge 3:================'

  b3 = Bytes.new("1b37373331363f78151b7f2b783431333d"\
                 "78397828372d363c78373e783a393b3736", :hex)

  # Try all ASCII values.
  (0..127).each do |i|
    key = Array.new(b3.length, i.chr).join
    result = b3 ^ Bytes.new(key)
    prob = Cryptanalysis.prob_english(result.ascii)

    puts "|#{i.chr}| #{result.ascii.inspect}" if prob > 0.6
  end
end

if DO_RUN.include?(:chal4)
  puts '================Challenge 4:================'

  File.readlines('set1_files/4.txt').each do |line|
    b = Bytes.new(line.chomp, :hex)

    (0..127).each do |i|
      guess = Array.new(b.length, i.chr).join
      result = b ^ Bytes.new(guess)
      prob = Cryptanalysis.prob_english(result.ascii)

      if prob > 0.6
        puts "Examining: #{b.hex}"
        puts "|#{i.chr}| #{result.ascii.inspect}"
      end
    end
  end
end

if DO_RUN.include?(:chal5)
  puts '================Challenge 5:================'

  b5 = Bytes.new("Burning 'em, if you ain't quick and nimble\n"\
                 "I go crazy when I hear a cymbal")
  b5key = Bytes.new("ICE")

  puts Crypto.vigenere(b5key, b5).hex
end

if DO_RUN.include?(:chal6)
  puts '================Challenge 6:================'

  File.open('set1_files/6.txt') do |f|
    ctext = Bytes.new(f.read().delete!("\n"), :base64)
    keysz = nil

    # Find a likely key size.
    top5 = Cryptanalysis.keysz_guesses(ctext)
    keysz = top5[0][0]

    # Transpose ciphertext into columns based on a given key size. Only valid
    # English--alphanumeric, punctuation, spaces, newlines--is shown in the
    # output. Repeat until the key is revealed.
    stride = (0..ctext.length).step(keysz)
    key_i = 0

    while key_i != keysz
      col = []

      stride.each { |i| col.push(ctext.bytes[i+key_i]) }
      col.compact!
      col = Bytes.new(col)

      (0..127).each do |i|
        # Do a single-character XOR.
        m = Crypto.vigenere(i.chr, col).ascii

        # Display valid English decryptions only.
        if m.match(/[[:alnum:][:punct:]\s\n]{#{m.length}}/)
          puts "[+] Decrypted with char #{i.chr.inspect}:", m.inspect 
        end
      end

      # Prompt for continuing to next column or exit.
      print "[?] Continue? (Y/n): "
      break if $stdin.getch.downcase == 'n'
      puts

      key_i += 1
      puts
    end

=begin
    # The answer.
    puts Crypto.vigenere('Terminator X: Bring the noise', ctext).ascii
=end
  end
end

if DO_RUN.include?(:chal7)
  puts '================Challenge 7:================'

  File.open('set1_files/7.txt') do |f|
    ctext = Bytes.new(f.read().delete!("\n"), :base64)

    cipher = OpenSSL::Cipher::AES128.new(:ECB).decrypt
    cipher.key = "YELLOW SUBMARINE"

    ptext = cipher.update(ctext.ascii) + cipher.final

    puts ptext
  end
end

if DO_RUN.include?(:chal8)
  puts '================Challenge 8:================'

  File.open('set1_files/8.txt').each_line do |line|
    b = Bytes.new(line.chomp, :hex)
    puts "ECB detected in ciphertext:", b.hex if Cryptanalysis.is_ecb?(b)
  end
end
