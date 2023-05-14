from pwn import *

# establish connection
p = remote("srng.bsides.shellmates.club", 443, ssl=True)

# the constants used in the generator
m = int("10ffff", 16)
l = int("101", 16)
e = int("d7fb", 16)

# initial state after constructor
i = 3
# rand = pow(i, time, m)

# first stage : random number generator
p.recvuntil(b'this: ')
numbers = p.recvline().decode()[:-2].split(', ')
print("numbers : ", numbers)

# update the state
i += 1 + len(numbers)
rand = int(numbers[-1])

# second stage : random padding genertor
p.recvuntil(b'this: ')
padding = p.recvuntil(b'.', drop=True).decode()
print("padding : ", padding, "->", len(padding))

# update the state
i += 1 + len(padding)
rand = ord(padding[-1])

# third stage : encrypting the flag
p.recvuntil(b'this: ')
flag_enc = bytes.fromhex(p.recvline().strip()[:-1].decode()).decode()
print(flag_enc, "->", len(flag_enc))

# continue updating the state, but this time by us
rand = pow(i, rand, l)
i += 1

# predicting the padding added to the ecnrypted flag
padding_length = rand
print("padding lenght : ", padding_length)

# jumping into after-padding state
for i in range(padding_length):
  rand = pow(i, rand, e)
  i += 1
  
# reconstructing the flag
flag= ''

for char in flag_enc[padding_length:]:
  # the random generator is broken now
  rand = pow(i, rand, e)
  i += 1
  # flag_char = enc_char ^ rand = (flag_char ^ rand) ^ rand
  flag += chr(ord(char) ^ rand)

print("flag is : ", flag) 
