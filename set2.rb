require './crypto'
require './cryptanalysis'

DO_RUN = [
  #:chal9,
  #:chal10,
  #:chal11,
  #:chal12,
  #:chal13,
  #:chal14,
  #:chal15,
  #:chal16
]

if DO_RUN.include?(:chal9)
  puts '================Challenge 9:================'

  p Crypto.pkcs7_padding('YELLOW SUBMARINE', 20).ascii
end

if DO_RUN.include?(:chal10)
  puts '================Challenge 10:================'

  File.open('files/10.txt') do |f|
    ctext = Bytes.new(f.read.delete!("\n"), :base64)

    cipher = Crypto::AES_CBC.new('YELLOW SUBMARINE')
    puts cipher.decrypt(ctext).ascii
  end
end

if DO_RUN.include?(:chal11)
  puts '================Challenge 11:================'
end

if DO_RUN.include?(:chal12)
  puts '================Challenge 12:================'
end

if DO_RUN.include?(:chal13)
  puts '================Challenge 13:================'
end

if DO_RUN.include?(:chal14)
  puts '================Challenge 14:================'
end

if DO_RUN.include?(:chal15)
  puts '================Challenge 15:================'
end

if DO_RUN.include?(:chal16)
  puts '================Challenge 16:================'
end
