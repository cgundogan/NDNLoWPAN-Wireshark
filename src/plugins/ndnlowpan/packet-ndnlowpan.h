/* packet-ndnlowpan.h
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

#define ETH_TYPE                        (0x0801)
#define NDNLOWPAN_H_TYPE                (1 << 7)
#define NDNLOWPAN_H_MINSUFFIX           (1 << 6)
#define NDNLOWPAN_H_MAXSUFFIX           (1 << 5)
#define NDNLOWPAN_H_PUBLISHERPUBKEY     (1 << 4)
#define NDNLOWPAN_H_EXCLUDE             (1 << 3)
#define NDNLOWPAN_H_CHILD               (1 << 2)
#define NDNLOWPAN_H_MUSTBEFRESH         (1 << 1)
#define NDNLOWPAN_H_INTLIFETIME         (1 << 0)

