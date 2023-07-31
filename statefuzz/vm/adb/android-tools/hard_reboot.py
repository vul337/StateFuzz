import serial
import time
import sys


def press(n):
	if n == 0:
		s.write(b'\x00')
		time.sleep(1)
		s.write(b'\x00')
		time.sleep(1)
		s.write(b'\x01')
		time.sleep(45)
		s.write(b'\x00')
		time.sleep(1)
	elif n == 1:
		s.write(b'\x10')
		time.sleep(1)
		s.write(b'\x10')
		time.sleep(1)
		s.write(b'\x11')
		time.sleep(45)
		s.write(b'\x10')
		time.sleep(1)
	elif n == 2:
		s.write(b'\x20')
		time.sleep(1)
		s.write(b'\x20')
		time.sleep(1)
		s.write(b'\x21')
		time.sleep(45)
		s.write(b'\x20')
		time.sleep(1)
	elif n == 3:
		s.write(b'\x30')
		time.sleep(1)
		s.write(b'\x30')
		time.sleep(1)
		s.write(b'\x31')
		time.sleep(45)
		s.write(b'\x30')
		time.sleep(1)


s = serial.Serial("/dev/ttyUSB0", 115200)
press(int(sys.argv[1]))