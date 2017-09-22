#!/usr/bin/env python3
#Copyright (c) 2017 Thomas Conroy
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.
import argparse, string, sys

#converts an uppercase letter to 1-26 alphabetic position
def letter_to_number(letter):
    return string.ascii_uppercase.index(letter) + 1

#convers a number 1-26 to A-Z
def number_to_letter(number):
    return string.ascii_uppercase[number - 1]

#helper function to iterate over the alphabet, numbers 1-26
def iterate_alphabet(start=1, end=26):
    for letter in string.ascii_uppercase[start-1:end]:
        yield letter

#representation of a rotor in the Enigma machine
class Rotor:
    def __init__(self, ring_setting, mapping, initial_setting):
        #the current rotation of the rotor, initial setting
        self.rotation = letter_to_number(initial_setting)
        #the internal wiring of the rotor (monoalphabetic substitution cipher)
        self.mapping = mapping
        #offset between the alphabet to the internal wiring
        if not ring_setting.isdigit():
            raise ValueError("Ring settings must be integers")
        self.ring_setting = int(ring_setting)
        if self.ring_setting < 1 or self.ring_setting > 26:
            raise ValueError("Ring settings must be 1-26 integers")

    #Rotors rotate one letter
    #1st rotor rotates each key press
    #2nd rotor rotates every 26 rotations of the 1st rotor
    def rotate(self):
        self.rotation = (self.rotation % 26) + 1

    #for signals sent forward through the rotor
    #letter is mapped using internal wiring and rotation
    def encrypt_forwards(self, letter):
        return self.mapping[(self.rotation - 1 + self.ring_setting - 1 + letter_to_number(letter) - 1) % 26]

    #for signals sent back through the rotor from the reflector
    def encrypt_backwards(self, letter):
        return number_to_letter(((self.mapping.index(letter) - (self.rotation - 1) - (self.ring_setting - 1) + 26) % 26) + 1)
        
class EnigmaMachine:
    def __init__(self, ring_settings, plugboard, initial_settings):
        ring_settings = ring_settings.split(' ')
        initial_settings = initial_settings.upper()
        
        #Mappings from Rotor I from Enigma I
        self.rotor1 = Rotor(ring_settings[0], 'EKMFLGDQVZNTOWYHXUSPAIBRCJ', initial_settings[0])
        #Mappings from Rotor II from Enigma I
        self.rotor2 = Rotor(ring_settings[1], 'AJDKSIRUXBLHWTMCQGZNPYFVOE', initial_settings[1])

        self.plugboard = {}
        plugboard = plugboard.upper()
        if len(plugboard) > 0:
            plugs = plugboard.split(' ')
            for plug in plugs:
                if len(plug) != 2:
                    raise ValueError("Group two letters together for each plug, e.g. 'PD KV TW'")
                if plug[0] in self.plugboard.keys() or plug[1] in self.plugboard.keys():
                    raise ValueError("Duplicate letter used in '" + plug + "' plugboard setting")
                if not plug.isalpha():
                    raise ValueError("Only letters are acceptable in plugboard settings. Error: '" + plug + "'")
                self.plugboard[plug[0]] = plug[1]
                self.plugboard[plug[1]] = plug[0]
        for letter in iterate_alphabet(): #add the rest of the letters as themselves on the plugboard
            if letter not in self.plugboard.keys():
                self.plugboard[letter] = letter

        self.initial_settings = initial_settings

        #Historical UKW-B reflector mapping
        reflector_mapping = 'YRUHQSLDPXNGOKMIEBFZCWVJAT'
        self.reflector = dict(zip(string.ascii_uppercase, reflector_mapping))
        

    #encryption is symmetric, messages are encrypted one letter at a time
    #each letter is sent through the plugboard, the rotors, then the reflector,
    #then back through the rotors, and then, finally, the plugboard again.
    def Encrypt(self, message=''):
        cipherText = ''
        letter_count = 0 #used to produce a space every five characters
        for letter in message:
            if letter.isalpha(): #only deal with alphabetic letters
                #The second rotor only rotates once per 26 rotations
                #of the first rotor. Q is the historical turnover letter for Rotor I
                #from Enigma I.
                #Rotors rotate before the letter is encrypted.
                if number_to_letter(self.rotor1.rotation) == 'Q':
                    self.rotor2.rotate()
                self.rotor1.rotate()

                #send letter through the machine
                letter1 = self.plugboard[letter]
                letter2 = self.rotor1.encrypt_forwards(letter1)
                letter3 = self.rotor2.encrypt_forwards(letter2)
                letter4 = self.reflector[letter3]
                letter5 = self.rotor2.encrypt_backwards(letter4)
                letter6 = self.rotor1.encrypt_backwards(letter5)
                letter7 = self.plugboard[letter6]
                cipherText += letter7
                letter_count = (letter_count + 1) % 5
                if letter_count == 0:
                    cipherText += ' '
        return cipherText

#set up help & parse commandline arguments for engima machine
def Parse_Enigma_Arguments():
    parser = argparse.ArgumentParser(description="Modified Enigma machine with two rotors. Enigma machines were used by the Germans in WWII to symmetrically encrypt and decrypt messages. More can be read about their use and workings at https://en.wikipedia.org/wiki/Enigma_machine\nThis machine uses two rotors instead of three (or four) as was used in WWII. This emulation of Enigma uses the I and II rotors, in that order, from 1930's Enigma I as well as the UKW-B reflector. This emulation requires the user to set the ring settings of the two rotors, the plugboard, and the initial setting of the rotors. The user is then prompted for text to be encrypted.", epilog='Example: ' + sys.argv[0] + ' "5 24" "IH VX PW LA ME OY FB QG TD ZC" JW')
    parser.add_argument('RingSettings', help="Each rotor's wiring relative to the alphabet, two 1-26 integers separated by a space, e.g. '4 15'")
    parser.add_argument('Plugboard', help='Plugboard letter matches, the form "AB CD EF" (pairs with spaces). Can be empty, i.e. "". Accepts a variable number of matchings. Letters are implicitly mapped to themselves if not specified, but this can also be explicitly done by mappings in the form "AA" or "CC".')
    parser.add_argument('InitialSettings', help='The initial rotor positions, two letters e.g. "JK"')
    parser.add_argument('-m', '--message', help='The message to en/decrypt. If not specificied, Enigma will read from stdin')
    args = parser.parse_args()
    return (args.RingSettings, args.Plugboard, args.InitialSettings, args.message)

def Validate_Input(args):
    ring_settings = args[0].split(' ')
    initial_settings = args[2].upper()
    if len(ring_settings) < 2:
        print("ERROR: Each rotor needs a ring setting, a 1-26 integer, e.g. '21 6'")
        return False
    else:
        if not initial_settings.isalpha() or len(initial_settings) != 2:
            print("ERROR: Each rotor needs a letter to start on, e.g. 'OU'")
            return False
    return True
    
#read arguments, set up engima machine, and encrypt
def Enigma_Main():
    args = Parse_Enigma_Arguments()
    if Validate_Input(args):
        try:
            enigma = EnigmaMachine(ring_settings=args[0], plugboard=args[1], initial_settings=args[2])
            #did the user specify the message in args?
            if args[3]:
                plainText = args[3].upper()
            else:
                plainText = input('> ').upper()
            cipherText = enigma.Encrypt(plainText)
            print(cipherText)
        except ValueError as error:
            print('ERROR:', error)

#run enigma if in the __main__ module
if __name__ == '__main__':
    Enigma_Main()
