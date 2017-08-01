/* packet-ndnlowpan.c
 *
 * Routines for NDNLoWPAN protocol packet disassembly
 * Copyright 2017 Cenk Gündoğan <cenk.guendogan@haw-hamburg.de>
 * Copyright 2017 Christopher Scherb <chistopher.scherb@unibas.ch>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-ndnlowpan.h"

static int proto_ndnlowpan = -1;
static int hf_ndnlowpan_H = -1;
static int hf_ndnlowpan_H_flag_type = -1;
static gint ett_ndnlowpan = -1;
static gint ett_ndnlowpan_H_flags = -1;

static const value_string ndnlowpan_H_type_names[] = {
    { 0, "Interest" },
    { 1, "Data" },
    { 3, NULL }
};


void
proto_register_ndnlowpan(void)
{
    proto_ndnlowpan = proto_register_protocol (
        "NDN for LoWPANs",/* name       */
        "NDNLoWPAN",      /* short name */
        "ndnlowpan"       /* abbrev     */
        );

    static hf_register_info hf[] = {
	{ &hf_ndnlowpan_H,
            { "NDNLoWPAN Compression Header", "ndnlowpan.H",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
	{ &hf_ndnlowpan_H_flag_type,
            { "Packet Type", "ndnlowpan.H.type",
            FT_BOOLEAN, 8,
            VALS(ndnlowpan_H_type_names), NDNLOWPAN_H_TYPE,
            NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_ndnlowpan,
	&ett_ndnlowpan_H_flags,
    };

    proto_register_field_array(proto_ndnlowpan, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

static int
dissect_ndnlowpan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NDNLoWPAN");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);


    proto_item *ti = proto_tree_add_item(tree, proto_ndnlowpan, tvb, 0, -1, ENC_NA);

    proto_tree *ndnlowpan_tree = proto_item_add_subtree(ti, ett_ndnlowpan);

    static const int * ndnlowpan_H_type_flags[] = {
	&hf_ndnlowpan_H_flag_type,
	NULL
    };

    (void) ndnlowpan_H_type_flags;

    proto_tree *ndnlowpan_H_tree;
    gint offset = 0;
    //proto_tree_add_bitmask(ndnlowpan_tree, tvb, offset, hf_ndnlowpan_H, ett_ndnlowpan_H_flags, ndnlowpan_H_type_flags, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(ndnlowpan_tree, hf_ndnlowpan_H, tvb, offset, 1, ENC_BIG_ENDIAN);
    ndnlowpan_H_tree = proto_item_add_subtree(ti, ett_ndnlowpan_H_flags);
    proto_tree_add_item(ndnlowpan_H_tree, hf_ndnlowpan_H_flag_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return tvb_captured_length(tvb);
    //return offset;
}

void
proto_reg_handoff_ndnlowpan(void)
{
    static dissector_handle_t eth_handle;

    eth_handle = create_dissector_handle(dissect_ndnlowpan, proto_ndnlowpan);
    dissector_add_uint("ethertype", ETH_TYPE, eth_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
