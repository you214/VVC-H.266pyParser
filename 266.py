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
      print('  forbidden_zero_bit', self.forbidden_zero_bit)
      print('  nuh_reserved_zero_bit', self.nuh_reserved_zero_bit)
      print('  nuh_layer_id', self.nuh_layer_id)
      print('  nal_unit_type', self.nal_unit_type)
      print('  nuh_temporal_id_plus1', self.nuh_temporal_id_plus1)

class video_parameter_set_rbsp(object):
   def __init__(self, s):
      """
      7.3.2.3 Video parameter set RBSP syntax
      """
      self.t = '\t'
      self.vps_video_parameter_set_id = s.read('uint:4')
      self.vps_max_layers_minus1 = s.read('uint:6')
      self.vps_max_sublayers_minus1 = s.read('uint:3')
      if self.vps_max_layers_minus1 > 0 & self.vps_max_sublayers_minus1 > 0:
         self.vps_default_ptl_dpb_hrd_max_tid_flag = s.read('uint:1')
      if self.vps_max_layers_minus1 > 0:
         self.vps_all_independent_layers_flag = s.read('uint:1')
      for i in range(self.vps_max_layers_minus1):
         self.vps_layer_id[i] = s.read('uint:6')
         if i > 0 & self.vps_all_independent_layers_flag == 0:
            self.vps_max_tid_ref_present_flag[i] = s.read('uint:1')
            for j in range(i):
               self.vps_direct_ref_layer_flag[i][j] = s.read('uint:1')
               if self.vps_max_tid_ref_present_flag[i] & self.vps_direct_ref_layer_flag[i][j]:
                  self.vps_max_tid_il_ref_pics_plus1[i][j] = s.read('uint:3')
      if self.vps_max_layers_minus1 > 0:
         if self.vps_all_independent_layers_flag:
            self.vps_each_layer_is_an_ols_flag = s.read('uint:1')
         if self.vps_each_layer_is_an_ols_flag == 0:
            if self.vps_all_independent_layers_flag == 0:
               self.vps_ols_mode_idc = s.read('uint:2')
            if self.vps_ols_mode_idc == 2 :
               self.vps_num_output_layer_sets_minus2 = s.read('uint:8')
               i = 1
               for i in range(self.vps_num_output_layer_sets_minus2 + 1):
                  for j in range(self.vps_max_layers_minus1):
                     self.vps_ols_output_layer_flag[ i ][ j ] = s.read('uint:1')
               self.vps_num_ptls_minus1 = s.read('uint:8')
            i = 0
            for i in range(self.vps_num_ptls_minus1):
               if i > 0:
                  self.vps_pt_present_flag[i] = s.read('uint:1')
               if( vps_default_ptl_dpb_hrd_max_tid_flag  == 0):
                  self.vps_ptl_max_tid[ i ] = s.read('uint:3')
            while not byte_alined():
               self.vps_ptl_alignment_zero_bit = s.read('uint:1') #equal to 0 */
            for i in range(self.vps_num_ptls_minus1):
               self.profile_tier_level( vps_pt_present_flag[ i ], vps_ptl_max_tid[ i ] )
            for i in range(self.TotalNumOlss):
               if self.vps_num_ptls_minus1 > 0 & self.vps_num_ptls_minus1 + 1 != self.TotalNumOlss:
                  self.vps_ols_ptl_idx[ i ] = s.read('uint:8')
            if not self.vps_each_layer_is_an_ols_flag:
               self.vps_num_dpb_params_minus1 = s.read('ue')
               if self.vps_max_sublayers_minus1 > 0:
                  self.vps_sublayer_dpb_params_present_flag = s.read('uint:1')
               for i in range (self.VpsNumDpbParams) :
                  if not self.vps_default_ptl_dpb_hrd_max_tid_flag:
                     self.vps_dpb_max_tid[i] = s.read('uint:3')
                  self.dpb_parameters( vps_dpb_max_tid[ i ], vps_sublayer_dpb_params_present_flag )
               for i in range(self.NumMultiLayerOlss):
                  self.vps_ols_dpb_pic_width[ i ] = s.read('ue')
                  self.vps_ols_dpb_pic_height[ i ] = s.read('ue')
                  self.vps_ols_dpb_chroma_format[ i ] = s.read('uint:2')
                  self.vps_ols_dpb_bitdepth_minus8[ i ] = s.read('ue')
                  if self.VpsNumDpbParams > 1 & self.VpsNumDpbParams == 1 != self.NumMultiLayerOlss:
                     self.vps_ols_dpb_params_idx[ i ] = s.read('ue')
                     
                  
                  
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

   NumBytesInRbsp = len(rbsp_byte)
   s = rbsp_byte

   nal_unit_type = n.nal_unit_type

   if nal_unit_type == NalUnitType.NAL_UNIT_TRAIL_NUT or \
      nal_unit_type == NalUnitType.NAL_UNIT_STSA_NUT:
         #slice_layer_rbsp()
         pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_RADL_NUT or \
      nal_unit_type == NalUnitType.NAL_UNIT_RASL_NUT:
         # slice_layer_rbsp()
         pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_VCL_4 or \
      nal_unit_type == NalUnitType.NAL_UNIT_VCL_5 or \
      nal_unit_type == NalUnitType.NAL_UNIT_VCL_6 :
         pass
   elif  nal_unit_type == NalUnitType.NAL_UNIT_IDR_W_RADL or \
      nal_unit_type == NalUnitType.NAL_UNIT_N_LP:
         #slice_layer_rbsp()
         pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_CRA_NUT or \
      nal_unit_type == NalUnitType.NAL_UNIT_GDR_NUT:
         #slice_layer_rbsp()
         pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_RSV_IRAP_11:
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_OPI_NUT:
      #operating_point_information_rbsp()
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_DCI_NUT:
      #decoding_capability_information_rbsp()
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_VPS_NUT:
      # video_parameter_set_rbsp()
      video_parameter_set_rbsp(s).show()
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_SPS_NUT:
      # seq_parameter_set_rbsp()
      seq_parameter_set_rbsp(s).show()
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_PPS_NUT:
      # pic_parameter_set_rbsp()
      pic_parameter_set_rbsp(s).show()      
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_PREFIX_APS_NUT or \
      nal_unit_type == NalUnitType.NAL_UNIT_SUFFIX_APS_NUT:
         pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_PH_NUT:
      # picture_header_rbsp()
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_AUD_NUT:
      # access_unit_delimiter_rbsp()
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_EOS_NUT:
      # end_of_seq_rbsp()
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_EOB_NUT:
      # end_of_bitstream_rbsp()
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_PREFIX_SEI_NUT or \
   nal_unit_type == NalUnitType.NAL_UNIT_SUFFIX_SEI_NUT:
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_FD_NUT:
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_RSV_NVCL_26 or \
      nal_unit_type == NalUnitType.NAL_UNIT_NVCL_27:
      pass
   elif nal_unit_type == NalUnitType.NAL_UNIT_UNSPEC_28 or \
      nal_unit_type == NalUnitType.NAL_UNIT_UNSPEC_29 or \
      nal_unit_type == NalUnitType.NAL_UNIT_UNSPEC_30 or \
      nal_unit_type == NalUnitType.NAL_UNIT_UNSPEC_31:
      pass

def main():
   
   F = 'out.vvc'
   s = BitStream(filename=F)
   
   nals = list(s.findall('0x000001', bytealigned=True))
   size = [y - x for x,y in zip(nals,nals[1:])]

   for i, n in zip(nals, size):
      print()
      print("!! Found NAL @ offset {0:d} ({0:#x})".format(int((i+24)/8)))
      read_nal_unit(s, i, int(n/8)) # bits to bytes   
   

if __name__ == "__main__":
    main()
