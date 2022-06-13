#!/usr/bin/env python


"""
- ae(v): context-adaptive arithmetic entropy-coded syntax element. The parsing process for this descriptor is
         specified in clause 9.3.
- b(8):  byte having any pattern of bit string (8 bits). The parsing process
         for this descriptor is specified by the return value of the function
         read_bits( 8 ).
- f(n):  fixed-pattern bit string using n bits written (from left to right)
         with the left bit first. The parsing process for this descriptor is specified
         by the return value of the function read_bits( n ).
- se(v): signed integer 0-th order Exp-Golomb-coded syntax element with the left bit first. The parsing process
         for this descriptor is specified in clause 9.2.
- u(n):  unsigned integer using n bits. When n is "v" in the syntax table, the number of bits varies in a manner
         dependent on the value of other syntax elements. The parsing process for this descriptor is specified by the
         return value of the function read_bits( n ) interpreted as a binary representation of an unsigned integer with
         most significant bit written first.
- ue(v): unsigned integer 0-th order Exp-Golomb-coded syntax element with the left bit first. The parsing
         process for this descriptor is specified in clause 9.2.

"""

import sys
import os
import re
from bitstring import BitArray, BitStream


class NalUnitType:
   """
   Table 5 - NAL unit type codes and NAL unit type classes
   """
   NAL_UNIT_TRAIL_NUT = 0
   NAL_UNIT_STSA_NUT = 1

   NAL_UNIT_RADL_NUT = 2
   NAL_UNIT_RASL_NUT = 3
   
   NAL_UNIT_VCL_4 = 4
   NAL_UNIT_VCL_5 = 5
   NAL_UNIT_VCL_6 = 6
   
   NAL_UNIT_IDR_W_RADL = 7
   NAL_UNIT_N_LP = 8
   
   NAL_UNIT_CRA_NUT = 9
   NAL_UNIT_GDR_NUT = 10
   
   NAL_UNIT_RSV_IRAP_11 = 11
   
   NAL_UNIT_OPI_NUT = 12
   NAL_UNIT_DCI_NUT = 13
   
   NAL_UNIT_VPS_NUT = 14
   NAL_UNIT_SPS_NUT = 15
   NAL_UNIT_PPS_NUT = 16
   
   NAL_UNIT_PREFIX_APS_NUT = 17
   NAL_UNIT_SUFFIX_APS_NUT = 18
   
   NAL_UNIT_PH_NUT = 19
   NAL_UNIT_AUD_NUT = 20
   
   NAL_UNIT_EOS_NUT = 21
   NAL_UNIT_EOB_NUT = 22
   
   NAL_UNIT_PREFIX_SEI_NUT = 23
   NAL_UNIT_SUFFIX_SEI_NUT = 24
   
   NAL_UNIT_FD_NUT = 25
   
   NAL_UNIT_RSV_NVCL_26 = 26
   NAL_UNIT_NVCL_27 = 27
   
   NAL_UNIT_UNSPEC_28 = 28
   NAL_UNIT_UNSPEC_29 = 29
   NAL_UNIT_UNSPEC_30 = 30
   NAL_UNIT_UNSPEC_31 = 31   
   

class nal_unit_header(object):
   def __init__(self, s):
      self.forbidden_zero_bit  = s.read('uint:1')
      self.nuh_reserved_zero_bit = s.read('uint:1')
      self.nuh_layer_id = s.read('uint:6')
      self.nal_unit_type = s.read('uint:5')
      self.nuh_temporal_id_plus1 = s.read('uint:3')

   def show(self):
      print('forbidden_zero_bit', self.forbidden_zero_bit)
      print('nuh_reserved_zero_bit', self.nuh_reserved_zero_bit)
      print('nuh_layer_id', self.nuh_layer_id)
      print('nal_unit_type', self.nal_unit_type)
      print('nuh_temporal_id_plus1', self.nuh_temporal_id_plus1)



def read_nal_unit(s, i, NumBytesInNalUnit):

   # Advance pointer and skip 24 bits, i.e. 0x000001
   s.pos = i + 24
   
   n = nal_unit_header(s)
   n.show()

   NumBytesInRbsp = 0
   i = 2
   rbsp_byte = BitStream()
   for i in range(NumBytesInNalUnit):
      if i + 2 < NumBytesInNalUnit and s.peek(24) == '0x000003':
         rbsp_byte.append(s.read('bits:8'))
         rbsp_byte.append(s.read('bits:8'))
         i =+ 2
         # emulation_prevention_three_byte # equal to 0x03
      else:
         rbsp_byte.append(s.read('bits:8'))

def main():
   
   F = 'out.vvc'
   #F = 'baskeQP1_GOF0_texture.bin'
   s = BitStream(filename=F)
   
   nals = list(s.findall('0x000001', bytealigned=True))
   size = [y - x for x,y in zip(nals,nals[1:])]

   for i, n in zip(nals, size):
      print()
      print("!! Found NAL @ offset {0:d} ({0:#x})".format(int((i+24)/8)))
      read_nal_unit(s, i, int(n/8)) # bits to bytes   
   

if __name__ == "__main__":
    main()
