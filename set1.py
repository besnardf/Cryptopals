#!/usr/bin/python

import base64
import itertools

def hex_to_base64(text):
	return base64.b64encode(text.decode('hex'))

#print "[+] Challenge 1 : " + hex_to_base64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')

def fixed_xor(text, key):
	output = ''
	text = text.decode('hex')
	key = key.decode('hex')
	for (a,b) in zip(text,key):
		output += chr(ord(a) ^ ord(b))
	return output.encode('hex')

#print "[+] Challenge 2 : " + fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965')

def single_byte_xor_cipher(text):
	output = []
	text = text.decode('hex')
	for i in xrange(0,255):
		xored = ''
		for a in text:
			xored += chr(ord(a) ^ i)
		xored = xored.strip()
		if all(ord(char) > 31 and ord(char) < 127 for char in xored):
			output.append(xored)
	common = ["E", "T", "A", "O", "I", "N", " ", "S", "H", "R", "D", "L", "U"][::-1]
	threshold = 0
	most_prob = ''
	for poss in output:
		score = 0
		for char in common:
			for c in poss:
				if c.lower() == char.lower():
					score += common.index(char) + 1
		if score > threshold:
			threshold = score
			most_prob = poss
	
	return most_prob

#print "[+] Challenge 3 : " + single_byte_xor_cipher('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')

def detect_single_character_xor(file):
	lines = open(file, "rb").readlines()
	output = []
	for line in lines:
		text = line.strip().decode('hex')
        	for i in xrange(0,255):
                	xored = ''
                	for a in text:
                        	xored += chr(ord(a) ^ i)
			xored = xored.strip()
                	if all(ord(char) > 31 and ord(char) < 127 for char in xored):
                        	output.append(xored)
	common = ["E", "T", "A", "O", "I", "N", " ", "S", "H", "R", "D", "L", "U"][::-1]
        threshold = 0
        most_prob = ''
        for poss in output:
                score = 0
                for char in common:
                        for c in poss:
                                if c.lower() == char.lower():
                                        score += common.index(char) + 1
                if score > threshold:
                        threshold = score
                        most_prob = poss

        return most_prob		

#print "[+] Challenge 4 : " + detect_single_character_xor("4.txt")

def repeating_key_xor(text, key):
	output = []
	if len(text) > len(key):
		output = [chr(ord(a) ^ ord(b)) for (a,b) in itertools.izip(text, itertools.cycle(key))]
	else:
		output = [chr(ord(a) ^ ord(b)) for (a,b) in itertools.izip(text, key)]

	return ''.join(output).encode("hex")

'''text = """Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""
key = "ICE"'''
#print "[+] Challenge 5 : " + repeating_key_xor(text, key)

def hamming_distance(a, b):
	a = ''.join(format(ord(x), "08b") for x in a)
	b = ''.join(format(ord(x), "08b") for x in b)
	count = 0
	if len(a) == len(b):
		for i in range(len(a)):
			if a[i] != b[i]:
				count += 1
		return count
	return "ERROR : lengths of arguments must be equal"

#assert hamming_distance("this is a test", "wokka wokka!!!") == 37
