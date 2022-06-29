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
               for i in range(self.vps_num_output_layer_sets_minus2 ):
                  for j in range(self.vps_max_layers_minus1):
                     self.vps_ols_output_layer_flag[ i ][ j ] = s.read('uint:1')
               self.vps_num_ptls_minus1 = s.read('uint:8')
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
                     


class seq_parameter_set_rbsp(object):
   def __init__(self, s):
      """
      7.3.2.4 sequence parameter set RBSP syntax
      """
      self.t = '\t'
      self.sps_seq_parameter_set_id = s.read('uint:4')
      self.sps_video_parameter_set_id = s.read('uint:4')
      self.sps_max_sublayers_minus1 = s.read('uint:3')
      self.sps_chroma_format_idc  = s.read('uint:2')
      self.sps_log2_ctu_size_minus5 = s.read('uint:2')
      self.sps_ptl_dpb_hrd_params_present_flag  = s.read('uint:1')
      if self.sps_ptl_dpb_hrd_params_present_flag :
         pass
         #self.profile_tier_level( 1, self.sps_max_sublayers_minus1 )
      self.sps_gdr_enabled_flag = s.read('uint:1')
      self.sps_ref_pic_resampling_enabled_flag  = s.read('uint:1')
      if self.sps_ref_pic_resampling_enabled_flag:
         self.sps_res_change_in_clvs_allowed_flag = s.read('uint:1')
      self.sps_pic_width_max_in_luma_samples = s.read('ue')
      self.sps_pic_height_max_in_luma_samples = s.read('ue')
      self.sps_conformance_window_flag = s.read('uint:1')
      if self.sps_conformance_window_flag:
         self.sps_conf_win_left_offset = s.read('ue')
         self.sps_conf_win_right_offset = s.read('ue')
         self.sps_conf_win_top_offset = s.read('ue')
         self.sps_conf_win_bottom_offset = s.read('ue')
      self.sps_subpic_info_present_flag = s.read('uint:1')
      if self.sps_subpic_info_present_flag:
         self.sps_num_subpics_minus1 = s.read('ue')
         if self.sps_num_subpics_minus1 > 0:
            self.sps_independent_subpics_flag  = s.read('uint:1')
            self.sps_subpic_same_size_flag  = s.read('uint:1')
         for i in range(self.sps_num_subpics_minus1):
            if not self.sps_subpic_same_size_flag or i ==  0:
               if i > 0 & self.sps_pic_width_max_in_luma_samples > CtbSizeY:
                  self.sps_subpic_ctu_top_left_x[ i ] = s.read('ue')
               if i > 0 & self.sps_pic_height_max_in_luma_samples > CtbSizeY:
                  self.sps_subpic_ctu_top_left_y[ i ] = s.read('ue')
               if i < self.sps_num_subpics_minus1 & self.sps_pic_width_max_in_luma_samples > CtbSizeY:
                  self.sps_subpic_width_minus1[ i ] = s.read('ue')
               if i < self.sps_num_subpics_minus1 & self.sps_pic_height_max_in_luma_samples > CtbSizeY:
                  self.sps_subpic_height_minus1[ i ] = s.read('ue')
            if not sps_independent_subpics_flag:
               self.sps_subpic_treated_as_pic_flag[ i ]  = s.read('uint:1')
               self.sps_loop_filter_across_subpic_enabled_flag[ i ]  = s.read('uint:1')
         self.sps_subpic_id_len_minus1  = s.read('ue')
         self.sps_subpic_id_mapping_explicitly_signalled_flag  = s.read('uint:1')
         if self.sps_subpic_id_mapping_explicitly_signalled_flag:
            self.sps_subpic_id_mapping_present_flag = s.read('uint:1')
            if self.sps_subpic_id_mapping_present_flag:
               for i in  i <= self.sps_num_subpics_minus1:
                  self.sps_subpic_id[ i ]  = s.read('ue')
         self.sps_bitdepth_minus8  = s.read('ue')
         self.sps_entropy_coding_sync_enabled_flag = s.read('uint:1')
         self.sps_entry_point_offsets_present_flag = s.read('uint:1')
         self.sps_log2_max_pic_order_cnt_lsb_minus4 = s.read('uint:4')
         self.sps_poc_msb_cycle_flag = s.read('uint:1')
         if self.sps_poc_msb_cycle_flag:
            self.sps_poc_msb_cycle_len_minus1 = s.read('ue')
         self.sps_num_extra_ph_bytes = s.read('uint:2')
         for i in range(self.sps_num_extra_ph_bytes * 8 ):
            self.sps_extra_ph_bit_present_flag[ i ] = s.read('uint:1')
         self.sps_num_extra_sh_bytes = s.read('uint:2')
         for i in range(self.sps_num_extra_sh_bytes * 8):
            self.sps_extra_sh_bit_present_flag[ i ] = s.read('uint:1')
         if self.sps_ptl_dpb_hrd_params_present_flag :
            if( self.sps_max_sublayers_minus1 > 0 ):
               self.sps_sublayer_dpb_params_flag = s.read('uint:1')
            dpb_parameters( self.sps_max_sublayers_minus1, self.sps_sublayer_dpb_params_flag )
         self.sps_log2_min_luma_coding_block_size_minus2 = s.read('ue')
         self.sps_partition_constraints_override_enabled_flag = s.read('uint:1')
         self.sps_log2_diff_min_qt_min_cb_intra_slice_luma = s.read('ue')
         self.sps_max_mtt_hierarchy_depth_intra_slice_luma = s.read('ue')
         if sps_max_mtt_hierarchy_depth_intra_slice_luma != 0:
            self.sps_log2_diff_max_bt_min_qt_intra_slice_luma = s.read('ue')
            self.sps_log2_diff_max_tt_min_qt_intra_slice_luma = s.read('ue')
         if self.sps_chroma_format_idc != 0:
            self.sps_qtbtt_dual_tree_intra_flag = s.read('uint:1')
         if self.sps_qtbtt_dual_tree_intra_flag:
            self.sps_log2_diff_min_qt_min_cb_intra_slice_chroma = s.read('ue')
            self.sps_max_mtt_hierarchy_depth_intra_slice_chroma = s.read('ue')
         if self.sps_max_mtt_hierarchy_depth_intra_slice_chroma != 0:
            self.sps_log2_diff_max_bt_min_qt_intra_slice_chroma = s.read('ue')
            self.sps_log2_diff_max_tt_min_qt_intra_slice_chroma = s.read('ue')
      if self.CtbSizeY > 32:
         self.sps_max_luma_transform_size_64_flag  = s.read('uint:1') 
      self.sps_transform_skip_enabled_flag = s.read('uint:1')
      if self.sps_transform_skip_enabled_flag: 
         self.sps_log2_transform_skip_max_size_minus2 = s.read('ue')
         self.sps_bdpcm_enabled_flag = s.read('uint:1')
         self.sps_mts_enabled_flag = s.read('uint:1')
         if self.sps_mts_enabled_flag :
            self.sps_explicit_mts_intra_enabled_flag = s.read('uint:1')
            self.sps_explicit_mts_inter_enabled_flag = s.read('uint:1')
         self.sps_lfnst_enabled_flag = s.read('uint:1')
         if self.sps_chroma_format_idc != 0:
            self.sps_joint_cbcr_enabled_flag = s.read('uint:1')
            self.sps_same_qp_table_for_chroma_flag = s.read('uint:1')
         #numQpTables = self.sps_same_qp_table_for_chroma_flag ? 1 : ( self.sps_joint_cbcr_enabled_flag ? 3 : 2 )
         numQpTables = 1 if self.sps_same_qp_table_for_chroma_flag else 3 if self.sps_joint_cbcr_enabled_flag else 2 
         for i in i < numQpTables:
            self.sps_qp_table_start_minus26[ i ] = s.read('se')
            self.sps_num_points_in_qp_table_minus1[ i ] = s.read('ue')
            for j in j <= sps_num_points_in_qp_table_minus1[ i ]:
               self.sps_delta_qp_in_val_minus1[ i ][ j ] = s.read('ue')
               self.sps_delta_qp_diff_val[ i ][ j ] = s.read('ue')
      self.sps_sao_enabled_flag = s.read('uint:1')
      self.sps_alf_enabled_flag = s.read('uint:1')
      if self.sps_alf_enabled_flag & self.sps_chroma_format_idc != 0:
         self.sps_ccalf_enabled_flag = s.read('uint:1')
      self.sps_lmcs_enabled_flag = s.read('uint:1')
      self.sps_weighted_pred_flag = s.read('uint:1')
      self.sps_weighted_bipred_flag = s.read('uint:1')
      self.sps_long_term_ref_pics_flag = s.read('uint:1')
      if self.sps_video_parameter_set_id > 0:
         self.sps_inter_layer_prediction_enabled_flag = s.read('uint:1')
      self.sps_idr_rpl_present_flag = s.read('uint:1')
      self.sps_rpl1_same_as_rpl0_flag = s.read('uint:1')
      #for i in i <  self.sps_rpl1_same_as_rpl0_flag ? 1 : 2:
      for i in i <  1 if self.sps_rpl1_same_as_rpl0_flag else  2:
         self.sps_num_ref_pic_lists[ i ] = s.read('ue')
         for j in j < sps_num_ref_pic_lists[ i ]:
            pass
            ref_pic_list_struct( i, j )
      self.sps_ref_wraparound_enabled_flag = s.read('uint:1')
      self.sps_temporal_mvp_enabled_flag = s.read('uint:1')
      if self.sps_temporal_mvp_enabled_flag:
         self.sps_sbtmvp_enabled_flag = s.read('uint:1')
      self.sps_amvr_enabled_flag  = s.read('uint:1')
      self.sps_bdof_enabled_flag = s.read('uint:1')
      if self.sps_bdof_enabled_flag:
         self.sps_bdof_control_present_in_ph_flag = s.read('uint:1')
      self.sps_smvd_enabled_flag = s.read('uint:1')
      self.sps_dmvr_enabled_flag = s.read('uint:1')
      if self.sps_dmvr_enabled_flag:
         self.sps_dmvr_control_present_in_ph_flag = s.read('uint:1')
      self.sps_mmvd_enabled_flag = s.read('uint:1')
      if self.sps_mmvd_enabled_flag:
         self.sps_mmvd_fullpel_only_enabled_flag = s.read('uint:1')
      self.sps_six_minus_max_num_merge_cand = s.read('ue')
      self.sps_sbt_enabled_flag = s.read('uint:1')
      self.sps_affine_enabled_flag = s.read('uint:1')
      if self.sps_affine_enabled_flag :
         self.sps_five_minus_max_num_subblock_merge_cand = s.read('ue')
         self.sps_6param_affine_enabled_flag = s.read('uint:1')
         if self.sps_amvr_enabled_flag:
            self.sps_affine_amvr_enabled_flag = s.read('uint:1')
         self.sps_affine_prof_enabled_flag = s.read('uint:1')
         if self.sps_affine_prof_enabled_flag:
            self.sps_prof_control_present_in_ph_flag = s.read('uint:1')
      self.sps_bcw_enabled_flag = s.read('uint:1')
      self.sps_ciip_enabled_flag = s.read('uint:1')
      if self.MaxNumMergeCand >= 2:
         self.sps_gpm_enabled_flag = s.read('uint:1')
      if self.sps_gpm_enabled_flag & self.MaxNumMergeCand >= 3:
         self.sps_max_num_merge_cand_minus_max_num_gpm_cand = s.read('ue')
      self.sps_log2_parallel_merge_level_minus2 = s.read('ue')
      self.sps_isp_enabled_flag = s.read('uint:1')
      self.sps_mrl_enabled_flag = s.read('uint:1')
      self.sps_mip_enabled_flag = s.read('uint:1')
      if self.sps_chroma_format_idc != 0:
         self.sps_cclm_enabled_flag = s.read('uint:1')
      if self.sps_chroma_format_idc == 1:
         self.sps_chroma_horizontal_collocated_flag = s.read('uint:1')
         self.sps_chroma_vertical_collocated_flag = s.read('uint:1')
      self.sps_palette_enabled_flag = s.read('uint:1')
      if self.sps_chroma_format_idc == 3 != self.sps_max_luma_transform_size_64_flag:
         self.sps_act_enabled_flag = s.read('uint:1')
      if self.sps_transform_skip_enabled_flag or self.sps_palette_enabled_flag:
         self.sps_min_qp_prime_ts = s.read('ue')
      self.sps_ibc_enabled_flag = s.read('uint:1')
      if self.sps_ibc_enabled_flag:
         self.sps_six_minus_max_num_ibc_merge_cand = s.read('ue')
      self.sps_ladf_enabled_flag = s.read('uint:1')
      if self.sps_ladf_enabled_flag:
         self.sps_num_ladf_intervals_minus2 = s.read('uint:1')
         self.sps_ladf_lowest_interval_qp_offset = s.read('se')
         for i in i < self.sps_num_ladf_intervals_minus2 + 1:
            self.sps_ladf_qp_offset[ i ] = s.read('se')
            self.sps_ladf_delta_threshold_minus1[ i ] = s.read('ue')
      self.sps_explicit_scaling_list_enabled_flag = s.read('uint:1')
      if self.sps_lfnst_enabled_flag & self.sps_explicit_scaling_list_enabled_flag:
         self.sps_scaling_matrix_for_lfnst_disabled_flag = s.read('uint:1')
      if self.sps_act_enabled_flag & self.sps_explicit_scaling_list_enabled_flag:
         self.sps_scaling_matrix_for_alternative_colour_space_disabled_flag = s.read('uint:1')
      if self.sps_scaling_matrix_for_alternative_colour_space_disabled_flag:
         self.sps_scaling_matrix_designated_colour_space_flag = s.read('uint:1')
      self.sps_dep_quant_enabled_flag = s.read('uint:1')
      self.sps_sign_data_hiding_enabled_flag = s.read('uint:1')
      self.sps_virtual_boundaries_enabled_flag = s.read('uint:1')
      if self.sps_virtual_boundaries_enabled_flag:
         self.sps_virtual_boundaries_present_flag = s.read('uint:1')
      if self.sps_virtual_boundaries_present_flag:
            self.sps_num_ver_virtual_boundaries = s.read('ue')
            for i in i < self.sps_num_ver_virtual_boundaries:
               self.sps_virtual_boundary_pos_x_minus1[ i ] = s.read('ue')
      self.sps_num_hor_virtual_boundaries = s.read('ue') 
      for i in i < sps_num_hor_virtual_boundaries:
         self.sps_virtual_boundary_pos_y_minus1[ i ] = s.read('ue')
      if self.sps_ptl_dpb_hrd_params_present_flag:
         self.sps_timing_hrd_params_present_flag = s.read('uint:1')
         if self.sps_timing_hrd_params_present_flag:
            pass
            general_timing_hrd_parameters( )
         if self.sps_max_sublayers_minus1 > 0:
            self.sps_sublayer_cpb_params_present_flag = s.read('uint:1')
            firstSubLayer = 0 if self.sps_sublayer_cpb_params_present_flag else self.sps_max_sublayers_minus1
            pass
            ols_timing_hrd_parameters( firstSubLayer, sps_max_sublayers_minus1 )
      self.sps_field_seq_flag = s.read('uint:1')
      self.sps_vui_parameters_present_flag = s.read('uint:1')
      if self.sps_vui_parameters_present_flag:
         self.sps_vui_payload_size_minus1 = s.read('ue')
         while( not byte_aligned( ) ):
            self.sps_vui_alignment_zero_bit
            pass
            vui_payload( sps_vui_payload_size_minus1 + 1 )
      self.sps_extension_flag = s.read('uint:1')
      if( self.sps_extension_flag ):
         while( more_rbsp_data( ) ):
            self.sps_extension_data_flag = s.read('uint:1')
      self.rbsp_trailing_bits( )


class dpb_parameters(MaxSubLayersMinus1, subLayerInfoFlag):
   def __init__(self):
      """
      7.3.4 DPB parameters syntax
      """
      v = 0 if self.subLayerInfoFlag else self.MaxSubLayersMinus1
      for v in range(MaxSubLayersMinus1):
         self.dpb_max_dec_pic_buffering_minus1[ i ] = s.read('ue')
         self.dpb_max_num_reorder_pics[ i ] = s.read('ue')
         self.dpb_max_latency_increase_plus1[ i ] = s.read('ue')
   def show(self):
      pass



class pic_parameter_set_rbsp(object):
   def __init__(self, s):
      """
      7.3.2.5 picture parameter set RBSP syntax
      """
      self.t = '\t'
      self.pps_pic_parametaer_set_id = s.read('uint:6')
      self.pps_seq_parameter_set_id = s.read('uint:4')
      self.pps_mixed_nalu_types_in_pic_flag = s.read('uint:1')
      self.pps_pic_width_in_luma_samples = s.read('ue')
      self.pps_pic_height_in_luma_samples = s.read('ue')
      self.pps_conformance_window_flag = s.read('uint:1')
      if( self.pps_conformance_window_flag ):
         self.pps_conf_win_left_offset = s.read('ue')
         self.pps_conf_win_right_offset =s.read('ue')
         self.pps_conf_win_top_offset =s.read('ue')
         self.pps_conf_win_bottom_offset = s.read('ue')
      pps_scaling_window_explicit_signalling_flag = s.read('uint:1')
      if( self.pps_scaling_window_explicit_signalling_flag):
         self.pps_scaling_win_left_offset = s.read('se')
         self.pps_scaling_win_right_offset = s.read('se')
         self.pps_scaling_win_top_offset = s.read('se')
         self.pps_scaling_win_bottom_offset = s.read('se')
      self.pps_output_flag_present_flag = s.read('uint:1')
      self.pps_no_pic_partition_flag = s.read('uint:1')
      self.pps_subpic_id_mapping_present_flag = s.read('uint:1')
      if( self.pps_subpic_id_mapping_present_flag ):
         if( not self.pps_no_pic_partition_flag ):
            self.pps_num_subpics_minus1 = s.read('ue')
            self.pps_subpic_id_len_minus1 = s.read('ue')
            for i in int(self.pps_num_subpics_minus1):
               self.pps_subpic_id[ i ] = s.read('uv')
      if( not self.pps_no_pic_partition_flag ):
         self.pps_log2_ctu_size_minus5 = s.read('uint:2')
         self.pps_num_exp_tile_columns_minus1 = s.read('ue')
         self.pps_num_exp_tile_rows_minus1 = s.read('ue')
         for i in self.pps_num_exp_tile_columns_minus1:
            self.pps_tile_column_width_minus1[ i ] = s.read('ue')
         for i in  self.pps_num_exp_tile_rows_minus1:
            self.pps_tile_row_height_minus1[ i ] = s.read('ue')
         if( self.NumTilesInPic > 1 ):
            self.pps_loop_filter_across_tiles_enabled_flag = s.read('uint:1')
            self.pps_rect_slice_flag =s.read('uint:1') 
         if( self.pps_rect_slice_flag ):
            self.pps_single_slice_per_subpic_flag = s.read('uint:1')
         if( self.pps_rect_slice_flag != self.pps_single_slice_per_subpic_flag ):
            self.pps_num_slices_in_pic_minus1 = s.read('ue')
            if( self.pps_num_slices_in_pic_minus1 > 1 ):
               self.pps_tile_idx_delta_present_flag =s.read('uint:1')
            for i in self.pps_num_slices_in_pic_minus1: 
               if( int(self.SliceTopLeftTileIdx[ i ] % self.NumTileColumns) != (int(self.NumTileColumns) - int(1)) ):
                  self.pps_slice_width_in_tiles_minus1[ i ] = s.read('ue')
               if( self.SliceTopLeftTileIdx[ i ] / self.NumTileColumns != self.NumTileRows - 1 & ( self.pps_tile_idx_delta_present_flag or self.SliceTopLeftTileIdx[ i ] % self.NumTileColumns == 0 ) ):
                  self.pps_slice_height_in_tiles_minus1[ i ] = s.read('ue')
               if( self.pps_slice_width_in_tiles_minus1[ i ] ==  0 & self.pps_slice_height_in_tiles_minus1[ i ] == 0 & self.RowHeightVal[ self.SliceTopLeftTileIdx[ i ] / self.NumTileColumns ] > 1 ):
                     self.pps_num_exp_slices_in_tile[ i ] = s.read('ue')
               for j in  self.pps_num_exp_slices_in_tile[ i ]:
                  self.pps_exp_slice_height_in_ctus_minus1[ i ][ j ] = s.read('ue')
               i += NumSlicesInTile[ i ] - 1
               if( self.pps_tile_idx_delta_present_flag & i < self.pps_num_slices_in_pic_minus1 ):
                  self.pps_tile_idx_delta_val[ i ] = s.read('se')
         if(  not self.pps_rect_slice_flag or  self.pps_single_slice_per_subpic_flag or self.pps_num_slices_in_pic_minus1 > 0 ):
            self.pps_loop_filter_across_slices_enabled_flag = s.read('uint:1')
      self.pps_cabac_init_present_flag = s.read('uint:1')
      for i in 1:
            self.pps_num_ref_idx_default_active_minus1[ i ] = s.read('ue')
            self.pps_rpl1_idx_present_flag = s.read('uint:1')
            self.pps_weighted_pred_flag = s.read('uint:1') 
      self.pps_weighted_bipred_flag = s.read('uint:1')
      self.pps_ref_wraparound_enabled_flag = s.read('uint:1')
      if( self.pps_ref_wraparound_enabled_flag ):
         self.pps_pic_width_minus_wraparound_offset = s.read('ue')
      self.pps_init_qp_minus26 = s.read('se')
      self.pps_cu_qp_delta_enabled_flag = s.read('uint:1')
      self.pps_chroma_tool_offsets_present_flag = s.read('uint:1')
      if( self.pps_chroma_tool_offsets_present_flag ):
         self.pps_cb_qp_offset = s.read('se')
         self.pps_cr_qp_offset = s.read('se')
         self.pps_joint_cbcr_qp_offset_present_flag = s.read('uint:1')
      if( self.pps_joint_cbcr_qp_offset_present_flag ):
         self.pps_joint_cbcr_qp_offset_value = s.read('se')
      self.pps_slice_chroma_qp_offsets_present_flag = s.read('uint:1')
      self.pps_cu_chroma_qp_offset_list_enabled_flag = s.read("uint:1")
      if( self.pps_cu_chroma_qp_offset_list_enabled_flag ):
         self.pps_chroma_qp_offset_list_len_minus1 = s.read('ue')
         for i in self.pps_chroma_qp_offset_list_len_minus1:
            self.pps_cb_qp_offset_list[ i ] = s.read('se')
            self.pps_cr_qp_offset_list[ i ] = s.read('se')
         if( self.pps_joint_cbcr_qp_offset_present_flag ):
               self.pps_joint_cbcr_qp_offset_list[ i ] = s.read('se')
      self.pps_deblocking_filter_control_present_flag = s.read('uint:1')
      if( pps_deblocking_filter_control_present_flag ):
         self.pps_deblocking_filter_override_enabled_flag = s.read('uint:1')
         self.pps_deblocking_filter_disabled_flag = s.read('uint:1')
         if not self.pps_no_pic_partition_flag &  self.pps_deblocking_filter_override_enabled_flag:
            self.pps_dbf_info_in_ph_flag = s.read('uint:1')
         if( not self.pps_deblocking_filter_disabled_flag ):
            self.pps_luma_beta_offset_div2 = s.read('se')
         self.pps_luma_tc_offset_div2 = s.read('se')
         if( self.pps_chroma_tool_offsets_present_flag ):
            self.pps_cb_beta_offset_div2 = s.read('se')
            self.pps_cb_tc_offset_div2 = s.read('se')
            self.pps_cr_beta_offset_div2 = s.read('se')
            self.pps_cr_tc_offset_div2 = s.read('se')
      if(  not self.pps_no_pic_partition_flag ):
         self.pps_rpl_info_in_ph_flag = s.read('uint:1')
         self.pps_sao_info_in_ph_flag = s.read('uint:1')
         self.pps_alf_info_in_ph_flag = s.read('uint:1')
         if( ( self.pps_weighted_pred_flag or self.pps_weighted_bipred_flag ) & self.pps_rpl_info_in_ph_flag ):
            self.pps_wp_info_in_ph_flag = s.read('uint:1')
         self.pps_qp_delta_info_in_ph_flag = s.read('uint:1')
      self.pps_picture_header_extension_present_flag = s.read('uint:1')
      self.pps_slice_header_extension_present_flag = s.read('uint:1')
      self.pps_extension_flag = s.read('uint:1')
      if( pps_extension_flag ):
         while( more_rbsp_data( )):
            self.pps_extension_data_flag = s.read('uint:1')



def read_nal_unit(s, i, NumBytesInNalUnit):

   # Advance pointer and skip 24 bits, i.e. 0x000001
   s.pos = i + 24
   
   n = nal_unit_header(s)
   n.show()

   NumBytesInRbsp = 0
   rbsp_byte = BitStream()
   for i in range(NumBytesInNalUnit - 3):
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