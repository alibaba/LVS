/*******************************************************************************

  Intel 10 Gigabit PCI Express Linux driver
  Copyright(c) 1999 - 2012 Intel Corporation.

  This program is free software; you can redistribute it and/or modify it
  under the terms and conditions of the GNU General Public License,
  version 2, as published by the Free Software Foundation.

  This program is distributed in the hope it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
  more details.

  You should have received a copy of the GNU General Public License along with
  this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.

  The full GNU General Public License is included in this distribution in
  the file called "COPYING".

  Contact Information:
  e1000-devel Mailing List <e1000-devel@lists.sourceforge.net>
  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497

*******************************************************************************/


#include "ixgbe_type.h"
#include "ixgbe_dcb.h"
#include "ixgbe_dcb_82599.h"

/**
 * ixgbe_dcb_get_tc_stats_82599 - Returns status for each traffic class
 * @hw: pointer to hardware structure
 * @stats: pointer to statistics structure
 * @tc_count:  Number of elements in bwg_array.
 *
 * This function returns the status data for each of the Traffic Classes in use.
 */
s32 ixgbe_dcb_get_tc_stats_82599(struct ixgbe_hw *hw,
				 struct ixgbe_hw_stats *stats,
				 u8 tc_count)
{
	int tc;

	if (tc_count > IXGBE_DCB_MAX_TRAFFIC_CLASS)
		return IXGBE_ERR_PARAM;
	/* Statistics pertaining to each traffic class */
	for (tc = 0; tc < tc_count; tc++) {
		/* Transmitted Packets */
		stats->qptc[tc] += IXGBE_READ_REG(hw, IXGBE_QPTC(tc));
		/* Transmitted Bytes (read low first to prevent missed carry) */
		stats->qbtc[tc] += IXGBE_READ_REG(hw, IXGBE_QBTC_L(tc));
		stats->qbtc[tc] +=
			(((u64)(IXGBE_READ_REG(hw, IXGBE_QBTC_H(tc)))) << 32);
		/* Received Packets */
		stats->qprc[tc] += IXGBE_READ_REG(hw, IXGBE_QPRC(tc));
		/* Received Bytes (read low first to prevent missed carry) */
		stats->qbrc[tc] += IXGBE_READ_REG(hw, IXGBE_QBRC_L(tc));
		stats->qbrc[tc] +=
			(((u64)(IXGBE_READ_REG(hw, IXGBE_QBRC_H(tc)))) << 32);

		/* Received Dropped Packet */
		stats->qprdc[tc] += IXGBE_READ_REG(hw, IXGBE_QPRDC(tc));
	}

	return 0;
}

/**
 * ixgbe_dcb_get_pfc_stats_82599 - Return CBFC status data
 * @hw: pointer to hardware structure
 * @stats: pointer to statistics structure
 * @tc_count:  Number of elements in bwg_array.
 *
 * This function returns the CBFC status data for each of the Traffic Classes.
 */
s32 ixgbe_dcb_get_pfc_stats_82599(struct ixgbe_hw *hw,
				  struct ixgbe_hw_stats *stats,
				  u8 tc_count)
{
	int tc;

	if (tc_count > IXGBE_DCB_MAX_TRAFFIC_CLASS)
		return IXGBE_ERR_PARAM;
	for (tc = 0; tc < tc_count; tc++) {
		/* Priority XOFF Transmitted */
		stats->pxofftxc[tc] += IXGBE_READ_REG(hw, IXGBE_PXOFFTXC(tc));
		/* Priority XOFF Received */
		stats->pxoffrxc[tc] += IXGBE_READ_REG(hw, IXGBE_PXOFFRXCNT(tc));
	}

	return 0;
}

/**
 * ixgbe_dcb_config_packet_buffers_82599 - Configure DCB packet buffers
 * @hw: pointer to hardware structure
 * @dcb_config: pointer to ixgbe_dcb_config structure
 *
 * Configure packet buffers for DCB mode.
 */
s32 ixgbe_dcb_config_packet_buffers_82599(struct ixgbe_hw *hw,
					  struct ixgbe_dcb_config *dcb_config)
{
	int num_tcs = dcb_config->num_tcs.pg_tcs;
	u32 rx_pb_size = hw->mac.rx_pb_size << IXGBE_RXPBSIZE_SHIFT;
	u32 rxpktsize;
	u32 txpktsize;
	u32 txpbthresh;
	u8  i = 0;

	/*
	 * This really means configure the first half of the TCs
	 * (Traffic Classes) to use 5/8 of the Rx packet buffer
	 * space.  To determine the size of the buffer for each TC,
	 * we are multiplying the average size by 5/4 and applying
	 * it to half of the traffic classes.
	 */
	if (dcb_config->rx_pba_cfg == ixgbe_dcb_pba_80_48) {
		rxpktsize = (rx_pb_size * 5) / (num_tcs * 4);
		rx_pb_size -= rxpktsize * (num_tcs / 2);
		for (; i < (num_tcs / 2); i++)
			IXGBE_WRITE_REG(hw, IXGBE_RXPBSIZE(i), rxpktsize);
	}

	/* Divide the remaining Rx packet buffer evenly among the TCs */
	rxpktsize = rx_pb_size / (num_tcs - i);
	for (; i < num_tcs; i++)
		IXGBE_WRITE_REG(hw, IXGBE_RXPBSIZE(i), rxpktsize);

	/*
	 * Setup Tx packet buffer and threshold equally for all TCs
	 * TXPBTHRESH register is set in K so divide by 1024 and subtract
	 * 10 since the largest packet we support is just over 9K.
	 */
	txpktsize = IXGBE_TXPBSIZE_MAX / num_tcs;
	txpbthresh = (txpktsize / 1024) - IXGBE_TXPKT_SIZE_MAX;
	for (i = 0; i < num_tcs; i++) {
		IXGBE_WRITE_REG(hw, IXGBE_TXPBSIZE(i), txpktsize);
		IXGBE_WRITE_REG(hw, IXGBE_TXPBTHRESH(i), txpbthresh);
	}

	/* Clear unused TCs, if any, to zero buffer size*/
	for (; i < IXGBE_DCB_MAX_TRAFFIC_CLASS; i++) {
		IXGBE_WRITE_REG(hw, IXGBE_RXPBSIZE(i), 0);
		IXGBE_WRITE_REG(hw, IXGBE_TXPBSIZE(i), 0);
		IXGBE_WRITE_REG(hw, IXGBE_TXPBTHRESH(i), 0);
	}

	return 0;
}

/**
 * ixgbe_dcb_config_rx_arbiter_82599 - Config Rx Data arbiter
 * @hw: pointer to hardware structure
 * @dcb_config: pointer to ixgbe_dcb_config structure
 *
 * Configure Rx Packet Arbiter and credits for each traffic class.
 */
s32 ixgbe_dcb_config_rx_arbiter_82599(struct ixgbe_hw *hw, u16 *refill,
				      u16 *max, u8 *bwg_id, u8 *tsa,
				      u8 *map)
{
	u32 reg = 0;
	u32 credit_refill = 0;
	u32 credit_max = 0;
	u8  i = 0;

	/*
	 * Disable the arbiter before changing parameters
	 * (always enable recycle mode; WSP)
	 */
	reg = IXGBE_RTRPCS_RRM | IXGBE_RTRPCS_RAC | IXGBE_RTRPCS_ARBDIS;
	IXGBE_WRITE_REG(hw, IXGBE_RTRPCS, reg);

	/*
	 * map all UPs to TCs. up_to_tc_bitmap for each TC has corresponding
	 * bits sets for the UPs that needs to be mappped to that TC.
	 * e.g if priorities 6 and 7 are to be mapped to a TC then the
	 * up_to_tc_bitmap value for that TC will be 11000000 in binary.
	 */
	reg = 0;
	for (i = 0; i < IXGBE_DCB_MAX_USER_PRIORITY; i++)
		reg |= (map[i] << (i * IXGBE_RTRUP2TC_UP_SHIFT));

	IXGBE_WRITE_REG(hw, IXGBE_RTRUP2TC, reg);

	/* Configure traffic class credits and priority */
	for (i = 0; i < IXGBE_DCB_MAX_TRAFFIC_CLASS; i++) {
		credit_refill = refill[i];
		credit_max = max[i];
		reg = credit_refill | (credit_max << IXGBE_RTRPT4C_MCL_SHIFT);

		reg |= (u32)(bwg_id[i]) << IXGBE_RTRPT4C_BWG_SHIFT;

		if (tsa[i] == ixgbe_dcb_tsa_strict)
			reg |= IXGBE_RTRPT4C_LSP;

		IXGBE_WRITE_REG(hw, IXGBE_RTRPT4C(i), reg);
	}

	/*
	 * Configure Rx packet plane (recycle mode; WSP) and
	 * enable arbiter
	 */
	reg = IXGBE_RTRPCS_RRM | IXGBE_RTRPCS_RAC;
	IXGBE_WRITE_REG(hw, IXGBE_RTRPCS, reg);

	return 0;
}

/**
 * ixgbe_dcb_config_tx_desc_arbiter_82599 - Config Tx Desc. arbiter
 * @hw: pointer to hardware structure
 * @dcb_config: pointer to ixgbe_dcb_config structure
 *
 * Configure Tx Descriptor Arbiter and credits for each traffic class.
 */
s32 ixgbe_dcb_config_tx_desc_arbiter_82599(struct ixgbe_hw *hw, u16 *refill,
					   u16 *max, u8 *bwg_id, u8 *tsa)
{
	u32 reg, max_credits;
	u8  i;

	/* Clear the per-Tx queue credits; we use per-TC instead */
	for (i = 0; i < 128; i++) {
		IXGBE_WRITE_REG(hw, IXGBE_RTTDQSEL, i);
		IXGBE_WRITE_REG(hw, IXGBE_RTTDT1C, 0);
	}

	/* Configure traffic class credits and priority */
	for (i = 0; i < IXGBE_DCB_MAX_TRAFFIC_CLASS; i++) {
		max_credits = max[i];
		reg = max_credits << IXGBE_RTTDT2C_MCL_SHIFT;
		reg |= refill[i];
		reg |= (u32)(bwg_id[i]) << IXGBE_RTTDT2C_BWG_SHIFT;

		if (tsa[i] == ixgbe_dcb_tsa_group_strict_cee)
			reg |= IXGBE_RTTDT2C_GSP;

		if (tsa[i] == ixgbe_dcb_tsa_strict)
			reg |= IXGBE_RTTDT2C_LSP;

		IXGBE_WRITE_REG(hw, IXGBE_RTTDT2C(i), reg);
	}

	/*
	 * Configure Tx descriptor plane (recycle mode; WSP) and
	 * enable arbiter
	 */
	reg = IXGBE_RTTDCS_TDPAC | IXGBE_RTTDCS_TDRM;
	IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, reg);

	return 0;
}

/**
 * ixgbe_dcb_config_tx_data_arbiter_82599 - Config Tx Data arbiter
 * @hw: pointer to hardware structure
 * @dcb_config: pointer to ixgbe_dcb_config structure
 *
 * Configure Tx Packet Arbiter and credits for each traffic class.
 */
s32 ixgbe_dcb_config_tx_data_arbiter_82599(struct ixgbe_hw *hw, u16 *refill,
					   u16 *max, u8 *bwg_id, u8 *tsa,
					   u8 *map)
{
	u32 reg;
	u8 i;

	/*
	 * Disable the arbiter before changing parameters
	 * (always enable recycle mode; SP; arb delay)
	 */
	reg = IXGBE_RTTPCS_TPPAC | IXGBE_RTTPCS_TPRM |
	      (IXGBE_RTTPCS_ARBD_DCB << IXGBE_RTTPCS_ARBD_SHIFT) |
	      IXGBE_RTTPCS_ARBDIS;
	IXGBE_WRITE_REG(hw, IXGBE_RTTPCS, reg);

	/*
	 * map all UPs to TCs. up_to_tc_bitmap for each TC has corresponding
	 * bits sets for the UPs that needs to be mappped to that TC.
	 * e.g if priorities 6 and 7 are to be mapped to a TC then the
	 * up_to_tc_bitmap value for that TC will be 11000000 in binary.
	 */
	reg = 0;
	for (i = 0; i < IXGBE_DCB_MAX_USER_PRIORITY; i++)
		reg |= (map[i] << (i * IXGBE_RTTUP2TC_UP_SHIFT));

	IXGBE_WRITE_REG(hw, IXGBE_RTTUP2TC, reg);

	/* Configure traffic class credits and priority */
	for (i = 0; i < IXGBE_DCB_MAX_TRAFFIC_CLASS; i++) {
		reg = refill[i];
		reg |= (u32)(max[i]) << IXGBE_RTTPT2C_MCL_SHIFT;
		reg |= (u32)(bwg_id[i]) << IXGBE_RTTPT2C_BWG_SHIFT;

		if (tsa[i] == ixgbe_dcb_tsa_group_strict_cee)
			reg |= IXGBE_RTTPT2C_GSP;

		if (tsa[i] == ixgbe_dcb_tsa_strict)
			reg |= IXGBE_RTTPT2C_LSP;

		IXGBE_WRITE_REG(hw, IXGBE_RTTPT2C(i), reg);
	}

	/*
	 * Configure Tx packet plane (recycle mode; SP; arb delay) and
	 * enable arbiter
	 */
	reg = IXGBE_RTTPCS_TPPAC | IXGBE_RTTPCS_TPRM |
	      (IXGBE_RTTPCS_ARBD_DCB << IXGBE_RTTPCS_ARBD_SHIFT);
	IXGBE_WRITE_REG(hw, IXGBE_RTTPCS, reg);

	return 0;
}

/**
 * ixgbe_dcb_config_pfc_82599 - Configure priority flow control
 * @hw: pointer to hardware structure
 * @pfc_en: enabled pfc bitmask
 * @map: priority to tc assignments indexed by priority
 *
 * Configure Priority Flow Control (PFC) for each traffic class.
 */
s32 ixgbe_dcb_config_pfc_82599(struct ixgbe_hw *hw, u8 pfc_en, u8 *map)
{
	u32 i, j, reg;
	u8 max_tc = 0;

	for (i = 0; i < IXGBE_DCB_MAX_TRAFFIC_CLASS; i++) {
		if (map[i] > max_tc)
			max_tc = map[i];
	}

#ifdef CONFIG_DCB
	/* Block LFC now that we're configuring PFC */
	hw->fc.requested_mode = ixgbe_fc_pfc;

#endif /* CONFIG_DCB */
	/* Configure PFC Tx thresholds per TC */
	for (i = 0; i < IXGBE_DCB_MAX_TRAFFIC_CLASS; i++) {
		int enabled = 0;

		if (i > max_tc) {
			reg = 0;
			IXGBE_WRITE_REG(hw, IXGBE_FCRTL_82599(i), reg);
			IXGBE_WRITE_REG(hw, IXGBE_FCRTH_82599(i), reg);
			continue;
		}

		for (j = 0; j < IXGBE_DCB_MAX_USER_PRIORITY; j++) {
			if ((map[j] == i) && (pfc_en & (1 << j))) {
				enabled = 1;
				break;
			}
		}

		reg = hw->fc.low_water << 10;

		if (enabled)
			reg |= IXGBE_FCRTL_XONE;
		IXGBE_WRITE_REG(hw, IXGBE_FCRTL_82599(i), reg);

		reg = hw->fc.high_water[i] << 10;
		if (enabled)
			reg |= IXGBE_FCRTH_FCEN;
		IXGBE_WRITE_REG(hw, IXGBE_FCRTH_82599(i), reg);
	}

	/* Configure pause time (2 TCs per register) */
	reg = hw->fc.pause_time | (hw->fc.pause_time << 16);
	for (i = 0; i < (IXGBE_DCB_MAX_TRAFFIC_CLASS / 2); i++)
		IXGBE_WRITE_REG(hw, IXGBE_FCTTV(i), reg);

	/* Configure flow control refresh threshold value */
	IXGBE_WRITE_REG(hw, IXGBE_FCRTV, hw->fc.pause_time / 2);

	/* Enable Transmit PFC */
	reg = 0;
	if (pfc_en)
		reg = IXGBE_FCCFG_TFCE_PRIORITY;
	IXGBE_WRITE_REG(hw, IXGBE_FCCFG, reg);

	/* Enable Receive PFC */
	reg = IXGBE_READ_REG(hw, IXGBE_MFLCN);
	reg |= IXGBE_MFLCN_DPF;
	reg &= ~(IXGBE_MFLCN_RFCE | IXGBE_MFLCN_RPFCE);
	if (pfc_en)
		reg |= IXGBE_MFLCN_RPFCE;

	if (hw->mac.type == ixgbe_mac_X540) {
		reg |= IXGBE_MFLCN_RPFCM;
		reg &= ~IXGBE_MFLCN_RPFCE_MASK;
		reg |= pfc_en << IXGBE_MFLCN_RPFCE_SHIFT;
	}

	IXGBE_WRITE_REG(hw, IXGBE_MFLCN, reg);

	return 0;
}

/**
 * ixgbe_dcb_config_tc_stats_82599 - Config traffic class statistics
 * @hw: pointer to hardware structure
 *
 * Configure queue statistics registers, all queues belonging to same traffic
 * class uses a single set of queue statistics counters.
 */
s32 ixgbe_dcb_config_tc_stats_82599(struct ixgbe_hw *hw,
				    struct ixgbe_dcb_config *dcb_config)
{
	u32 reg = 0;
	u8  i   = 0;
	u8 tc_count = 8;
	bool vt_mode = false;

	if (dcb_config != NULL) {
		tc_count = dcb_config->num_tcs.pg_tcs;
		vt_mode = dcb_config->vt_mode;
	}

	if (!((tc_count == 8 && vt_mode == false) || tc_count == 4))
		return IXGBE_ERR_PARAM;

	if (tc_count == 8 && vt_mode == false) {
		/*
		 * Receive Queues stats setting
		 * 32 RQSMR registers, each configuring 4 queues.
		 *
		 * Set all 16 queues of each TC to the same stat
		 * with TC 'n' going to stat 'n'.
		 */
		for (i = 0; i < 32; i++) {
			reg = 0x01010101 * (i / 4);
			IXGBE_WRITE_REG(hw, IXGBE_RQSMR(i), reg);
		}
		/*
		 * Transmit Queues stats setting
		 * 32 TQSM registers, each controlling 4 queues.
		 *
		 * Set all queues of each TC to the same stat
		 * with TC 'n' going to stat 'n'.
		 * Tx queues are allocated non-uniformly to TCs:
		 * 32, 32, 16, 16, 8, 8, 8, 8.
		 */
		for (i = 0; i < 32; i++) {
			if (i < 8)
				reg = 0x00000000;
			else if (i < 16)
				reg = 0x01010101;
			else if (i < 20)
				reg = 0x02020202;
			else if (i < 24)
				reg = 0x03030303;
			else if (i < 26)
				reg = 0x04040404;
			else if (i < 28)
				reg = 0x05050505;
			else if (i < 30)
				reg = 0x06060606;
			else
				reg = 0x07070707;
			IXGBE_WRITE_REG(hw, IXGBE_TQSM(i), reg);
		}
	} else if (tc_count == 4 && vt_mode == false) {
		/*
		 * Receive Queues stats setting
		 * 32 RQSMR registers, each configuring 4 queues.
		 *
		 * Set all 16 queues of each TC to the same stat
		 * with TC 'n' going to stat 'n'.
		 */
		for (i = 0; i < 32; i++) {
			if (i % 8 > 3)
				/* In 4 TC mode, odd 16-queue ranges are
				 *  not used.
				*/
				continue;
			reg = 0x01010101 * (i / 8);
			IXGBE_WRITE_REG(hw, IXGBE_RQSMR(i), reg);
		}
		/*
		 * Transmit Queues stats setting
		 * 32 TQSM registers, each controlling 4 queues.
		 *
		 * Set all queues of each TC to the same stat
		 * with TC 'n' going to stat 'n'.
		 * Tx queues are allocated non-uniformly to TCs:
		 * 64, 32, 16, 16.
		 */
		for (i = 0; i < 32; i++) {
			if (i < 16)
				reg = 0x00000000;
			else if (i < 24)
				reg = 0x01010101;
			else if (i < 28)
				reg = 0x02020202;
			else
				reg = 0x03030303;
			IXGBE_WRITE_REG(hw, IXGBE_TQSM(i), reg);
		}
	} else if (tc_count == 4 && vt_mode == true) {
		/*
		 * Receive Queues stats setting
		 * 32 RQSMR registers, each configuring 4 queues.
		 *
		 * Queue Indexing in 32 VF with DCB mode maps 4 TC's to each
		 * pool. Set all 32 queues of each TC across pools to the same
		 * stat with TC 'n' going to stat 'n'.
		 */
		for (i = 0; i < 32; i++)
			IXGBE_WRITE_REG(hw, IXGBE_RQSMR(i), 0x03020100);
		/*
		 * Transmit Queues stats setting
		 * 32 TQSM registers, each controlling 4 queues.
		 *
		 * Queue Indexing in 32 VF with DCB mode maps 4 TC's to each
		 * pool. Set all 32 queues of each TC across pools to the same
		 * stat with TC 'n' going to stat 'n'.
		 */
		for (i = 0; i < 32; i++)
			IXGBE_WRITE_REG(hw, IXGBE_TQSM(i), 0x03020100);
	}

	return 0;
}

/**
 * ixgbe_dcb_config_82599 - Configure general DCB parameters
 * @hw: pointer to hardware structure
 * @dcb_config: pointer to ixgbe_dcb_config structure
 *
 * Configure general DCB parameters.
 */
s32 ixgbe_dcb_config_82599(struct ixgbe_hw *hw,
			   struct ixgbe_dcb_config *dcb_config)
{
	u32 reg;
	u32 q;

	/* Disable the Tx desc arbiter so that MTQC can be changed */
	reg = IXGBE_READ_REG(hw, IXGBE_RTTDCS);
	reg |= IXGBE_RTTDCS_ARBDIS;
	IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, reg);

	reg = IXGBE_READ_REG(hw, IXGBE_MRQC);
	if (dcb_config->num_tcs.pg_tcs == 8) {
		/* Enable DCB for Rx with 8 TCs */
		switch (reg & IXGBE_MRQC_MRQE_MASK) {
		case 0:
		case IXGBE_MRQC_RT4TCEN:
			/* RSS disabled cases */
			reg = (reg & ~IXGBE_MRQC_MRQE_MASK) |
			      IXGBE_MRQC_RT8TCEN;
			break;
		case IXGBE_MRQC_RSSEN:
		case IXGBE_MRQC_RTRSS4TCEN:
			/* RSS enabled cases */
			reg = (reg & ~IXGBE_MRQC_MRQE_MASK) |
			      IXGBE_MRQC_RTRSS8TCEN;
			break;
		default:
			/*
			 * Unsupported value, assume stale data,
			 * overwrite no RSS
			 */
			reg = (reg & ~IXGBE_MRQC_MRQE_MASK) |
			      IXGBE_MRQC_RT8TCEN;
		}
	}
	if (dcb_config->num_tcs.pg_tcs == 4) {
		/* We support both VT-on and VT-off with 4 TCs. */
		if (dcb_config->vt_mode)
			reg = (reg & ~IXGBE_MRQC_MRQE_MASK) |
			      IXGBE_MRQC_VMDQRT4TCEN;
		else
			reg = (reg & ~IXGBE_MRQC_MRQE_MASK) |
			      IXGBE_MRQC_RTRSS4TCEN;
	}
	IXGBE_WRITE_REG(hw, IXGBE_MRQC, reg);

	/* Enable DCB for Tx with 8 TCs */
	if (dcb_config->num_tcs.pg_tcs == 8)
		reg = IXGBE_MTQC_RT_ENA | IXGBE_MTQC_8TC_8TQ;
	else {
		/* We support both VT-on and VT-off with 4 TCs. */
		reg = IXGBE_MTQC_RT_ENA | IXGBE_MTQC_4TC_4TQ;
		if (dcb_config->vt_mode)
			reg |= IXGBE_MTQC_VT_ENA;
	}
	IXGBE_WRITE_REG(hw, IXGBE_MTQC, reg);

	/* Disable drop for all queues */
	for (q = 0; q < 128; q++)
		IXGBE_WRITE_REG(hw, IXGBE_QDE,
				(IXGBE_QDE_WRITE | (q << IXGBE_QDE_IDX_SHIFT)));

	/* Enable the Tx desc arbiter */
	reg = IXGBE_READ_REG(hw, IXGBE_RTTDCS);
	reg &= ~IXGBE_RTTDCS_ARBDIS;
	IXGBE_WRITE_REG(hw, IXGBE_RTTDCS, reg);

	/* Enable Security TX Buffer IFG for DCB */
	reg = IXGBE_READ_REG(hw, IXGBE_SECTXMINIFG);
	reg |= IXGBE_SECTX_DCB;
	IXGBE_WRITE_REG(hw, IXGBE_SECTXMINIFG, reg);

	return 0;
}

/**
 * ixgbe_dcb_hw_config_82599 - Configure and enable DCB
 * @hw: pointer to hardware structure
 * @dcb_config: pointer to ixgbe_dcb_config structure
 *
 * Configure dcb settings and enable dcb mode.
 */
s32 ixgbe_dcb_hw_config_82599(struct ixgbe_hw *hw, int link_speed, u8 pfc_en,
			      u16 *refill, u16 *max, u8 *bwg_id, u8 *tsa,
			      u8 *map)
{

	ixgbe_dcb_config_rx_arbiter_82599(hw, refill, max, bwg_id, tsa,
					  map);
	ixgbe_dcb_config_tx_desc_arbiter_82599(hw, refill, max, bwg_id,
					       tsa);
	ixgbe_dcb_config_tx_data_arbiter_82599(hw, refill, max, bwg_id,
					       tsa, map);
	ixgbe_dcb_config_pfc_82599(hw, pfc_en, map);


	return 0;
}

