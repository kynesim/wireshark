/* packet-rtps2.h
 * ~~~~~~~~~~~~~~
 *
 * Routines for Real-Time Publish-Subscribe Protocol (RTPS) dissection
 *
 * Copyright 2005, Fabrizio Bertocci <fabrizio@rti.com>
 * Real-Time Innovations, Inc.
 * 385 Moffett Park Drive
 * Sunnyvale, CA 94089
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *                  -------------------------------------
 *
 * This is the RTPS packet dissector for RTPS version 2.x
 *
 * RTPS protocol was initially developed by Real-Time Innovations, Inc. as wire 
 * protocol for Data Distribution System, and then adopted as a standard by
 * the Object Management Group (as version 2.0).
 *
 * Additional information at:
 *   Full OMG DDS Standard Specification: 
 *                             http://www.omg.org/cgi-bin/doc?ptc/2003-07-07
 *   
 *   RTI DDS and RTPS information: http://www.rti.com/resources.html
 *
 */


/* Note: This file is only included from packet-rtps2.c, so there is no risk
 * of namespace conflicts with all those macros.
 */
 
#ifndef _TYPEDEFS_DEFINES_RTPS2_H
#define _TYPEDEFS_DEFINES_RTPS2_H

#ifdef __cplusplus
extern "C" {
#endif



/* Traffic type */
#define PORT_BASE                       (7400)
#define PORT_METATRAFFIC_UNICAST        (0)
#define PORT_USERTRAFFIC_MULTICAST      (1)
#define PORT_METATRAFFIC_MULTICAST      (2)
#define PORT_USERTRAFFIC_UNICAST        (3)

/* Flags defined in the 'flag' bitmask of a submessage */
#define FLAG_E                  (0x01)  /* Common to all the submessages */
#define FLAG_DATA_Q_RTPS2       (0x02)
#define FLAG_DATA_D_RTPS2       (0x04)
#define FLAG_DATA_H             (0x08)
#define FLAG_DATA_I             (0x10)

#define FLAG_DATA_FRAG_Q        (0x02)
#define FLAG_DATA_FRAG_H        (0x04)


#define FLAG_NOKEY_DATA_Q       (0x02)
#define FLAG_NOKEY_DATA_D       (0x04)
#define FLAG_NOKEY_DATA_FRAG_Q  (0x02)
#define FLAG_NOKEY_DATA_FRAG_D  (0x04)
#define FLAG_ACKNACK_F          (0x02)

#define FLAG_HEARTBEAT_F        (0x02)
#define FLAG_HEARTBEAT_L        (0x04)

#define FLAG_INFO_TS_T          (0x02)

#define FLAG_INFO_REPLY_IP4_M   (0x02)

#define FLAG_INFO_REPLY_M       (0x02)

#define FLAG_RTPS_DATA_Q        (0x02)
#define FLAG_RTPS_DATA_D        (0x04)
#define FLAG_RTPS_DATA_K        (0x08)

#define FLAG_RTPS_DATA_FRAG_Q   (0x02)
#define FLAG_RTPS_DATA_FRAG_K   (0x04)

#define FLAG_RTPS_DATA_BATCH_Q  (0x02)

#define FLAG_SAMPLE_INFO_T      (0x01)
#define FLAG_SAMPLE_INFO_Q      (0x02)
#define FLAG_SAMPLE_INFO_O      (0x04)
#define FLAG_SAMPLE_INFO_D      (0x08)
#define FLAG_SAMPLE_INFO_I      (0x10)
#define FLAG_SAMPLE_INFO_K      (0x20)


/* The following PIDs are defined since RTPS 1.0 */
#define PID_DEFAULT_MULTICAST_LOCATOR           (0x0048)
#define PID_TRANSPORT_PRIORITY                  (0x0049)
#define PID_CONTENT_FILTER_INFO                 (0x0055)
#define PID_DIRECTED_WRITE                      (0x0057)
#define PID_BUILTIN_ENDPOINT_SET                (0x0058)
#define PID_PROPERTY_LIST                       (0x0059)        /* RTI DDS 4.2e and newer */
#define PID_ENDPOINT_GUID                       (0x005a)
#define PID_TYPE_MAX_SIZE_SERIALIZED            (0x0060)
#define PID_ORIGINAL_WRITER_INFO                (0x0061)
#define PID_ENTITY_NAME                         (0x0062)
#define PID_KEY_HASH                            (0x0070)
#define PID_STATUS_INFO                         (0x0071)

/* Vendor-specific: RTI */
#define PID_PRODUCT_VERSION                     (0x8000)
#define PID_PLUGIN_PROMISCUITY_KIND             (0x8001)
#define PID_ENTITY_VIRTUAL_GUID                 (0x8002)
#define PID_SERVICE_KIND                        (0x8003)
#define PID_TYPECODE_RTPS2                      (0x8004)        /* Was: 0x47 in RTPS 1.2 */
#define PID_DISABLE_POSITIVE_ACKS               (0x8005)
#define PID_LOCATOR_FILTER_LIST                 (0x8006)


/* appId.appKind possible values */
#define APPKIND_UNKNOWN                         (0x00)
#define APPKIND_MANAGED_APPLICATION             (0x01)
#define APPKIND_MANAGER                         (0x02)



/* Predefined EntityIds */
#define ENTITYID_UNKNOWN                                (0x00000000)
#define ENTITYID_PARTICIPANT                            (0x000001c1)
#define ENTITYID_SEDP_BUILTIN_TOPIC_WRITER              (0x000002c2)        /* Was: ENTITYID_BUILTIN_TOPIC_WRITER */
#define ENTITYID_SEDP_BUILTIN_TOPIC_READER              (0x000002c7)        /* Was: ENTITYID_BUILTIN_TOPIC_READER */
#define ENTITYID_SEDP_BUILTIN_PUBLICATIONS_WRITER       (0x000003c2)        /* Was: ENTITYID_BUILTIN_PUBLICATIONS_WRITER */
#define ENTITYID_SEDP_BUILTIN_PUBLICATIONS_READER       (0x000003c7)        /* Was: ENTITYID_BUILTIN_PUBLICATIONS_READER */
#define ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_WRITER      (0x000004c2)        /* Was: ENTITYID_BUILTIN_SUBSCRIPTIONS_WRITER */
#define ENTITYID_SEDP_BUILTIN_SUBSCRIPTIONS_READER      (0x000004c7)        /* Was: ENTITYID_BUILTIN_SUBSCRIPTIONS_READER */
#define ENTITYID_SPDP_BUILTIN_PARTICIPANT_WRITER        (0x000100c2)        /* Was: ENTITYID_BUILTIN_SDP_PARTICIPANT_WRITER */
#define ENTITYID_SPDP_BUILTIN_PARTICIPANT_READER        (0x000100c7)        /* Was: ENTITYID_BUILTIN_SDP_PARTICIPANT_READER */
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_WRITER (0x000200c2)
#define ENTITYID_P2P_BUILTIN_PARTICIPANT_MESSAGE_READER (0x000200c7)


/* Deprecated EntityId */
#define ENTITYID_APPLICATIONS_WRITER                    (0x000001c2)
#define ENTITYID_APPLICATIONS_READER                    (0x000001c7)
#define ENTITYID_CLIENTS_WRITER                         (0x000005c2)
#define ENTITYID_CLIENTS_READER                         (0x000005c7)
#define ENTITYID_SERVICES_WRITER                        (0x000006c2)
#define ENTITYID_SERVICES_READER                        (0x000006c7)
#define ENTITYID_MANAGERS_WRITER                        (0x000007c2)
#define ENTITYID_MANAGERS_READER                        (0x000007c7)
#define ENTITYID_APPLICATION_SELF                       (0x000008c1)
#define ENTITYID_APPLICATION_SELF_WRITER                (0x000008c2)
#define ENTITYID_APPLICATION_SELF_READER                (0x000008c7)

/* Predefined Entity Kind */
#define ENTITYKIND_APPDEF_UNKNOWN                       (0x00)
#define ENTITYKIND_APPDEF_PARTICIPANT                   (0x01)
#define ENTITYKIND_APPDEF_WRITER_WITH_KEY               (0x02)
#define ENTITYKIND_APPDEF_WRITER_NO_KEY                 (0x03)
#define ENTITYKIND_APPDEF_READER_NO_KEY                 (0x04)
#define ENTITYKIND_APPDEF_READER_WITH_KEY               (0x07)
#define ENTITYKIND_BUILTIN_PARTICIPANT                  (0xc1)
#define ENTITYKIND_BUILTIN_WRITER_WITH_KEY              (0xc2)
#define ENTITYKIND_BUILTIN_WRITER_NO_KEY                (0xc3)
#define ENTITYKIND_BUILTIN_READER_NO_KEY                (0xc4)
#define ENTITYKIND_BUILTIN_READER_WITH_KEY              (0xc7)


/* Submessage Type */
#define SUBMESSAGE_PAD                                  (0x01)
#define SUBMESSAGE_DATA                                 (0x02)
#define SUBMESSAGE_NOKEY_DATA                           (0x03)
#define SUBMESSAGE_ACKNACK                              (0x06)
#define SUBMESSAGE_HEARTBEAT                            (0x07)
#define SUBMESSAGE_GAP                                  (0x08)
#define SUBMESSAGE_INFO_TS                              (0x09)
#define SUBMESSAGE_INFO_SRC                             (0x0c)
#define SUBMESSAGE_INFO_REPLY_IP4                       (0x0d)
#define SUBMESSAGE_INFO_DST                             (0x0e)
#define SUBMESSAGE_INFO_REPLY                           (0x0f)

#define SUBMESSAGE_DATA_FRAG                            (0x10)  /* RTPS 2.0 Only */
#define SUBMESSAGE_NOKEY_DATA_FRAG                      (0x11)  /* RTPS 2.0 Only */
#define SUBMESSAGE_NACK_FRAG                            (0x12)  /* RTPS 2.0 Only */
#define SUBMESSAGE_HEARTBEAT_FRAG                       (0x13)  /* RTPS 2.0 Only */

#define SUBMESSAGE_RTPS_DATA_SESSION                    (0x14)  /* RTPS 2.1 only */
#define SUBMESSAGE_RTPS_DATA                            (0x15)  /* RTPS 2.1 only */
#define SUBMESSAGE_RTPS_DATA_FRAG                       (0x16)  /* RTPS 2.1 only */
#define SUBMESSAGE_ACKNACK_BATCH                        (0x17)  /* RTPS 2.1 only */
#define SUBMESSAGE_RTPS_DATA_BATCH                      (0x18)  /* RTPS 2.1 Only */
#define SUBMESSAGE_HEARTBEAT_BATCH                      (0x19)  /* RTPS 2.1 only */
#define SUBMESSAGE_ACKNACK_SESSION                      (0x1a)  /* RTPS 2.1 only */
#define SUBMESSAGE_HEARTBEAT_SESSION                    (0x1b)  /* RTPS 2.1 only */

/* Data encapsulation */
#define ENCAPSULATION_CDR_BE            (0x0000)
#define ENCAPSULATION_CDR_LE            (0x0001)
#define ENCAPSULATION_PL_CDR_BE         (0x0002)
#define ENCAPSULATION_PL_CDR_LE         (0x0003)

/* Parameter Liveliness */
#define LIVELINESS_AUTOMATIC            (0)
#define LIVELINESS_BY_PARTICIPANT       (1)
#define LIVELINESS_BY_TOPIC             (2)

/* Parameter Durability */
#define DURABILITY_VOLATILE             (0)
#define DURABILITY_TRANSIENT_LOCAL      (1)
#define DURABILITY_TRANSIENT            (2)
#define DURABILITY_PERSISTENT           (3)

/* Parameter Ownership */
#define OWNERSHIP_SHARED                (0)
#define OWNERSHIP_EXCLUSIVE             (1)

/* Parameter Presentation */
#define PRESENTATION_INSTANCE           (0)
#define PRESENTATION_TOPIC              (1)
#define PRESENTATION_GROUP              (2)


#define LOCATOR_KIND_INVALID            (-1)
#define LOCATOR_KIND_RESERVED           (0)
#define LOCATOR_KIND_UDPV4              (1)
#define LOCATOR_KIND_UDPV6              (2)

/* History Kind */
#define HISTORY_KIND_KEEP_LAST          (0)
#define HISTORY_KIND_KEEP_ALL           (1)

/* Reliability Values */
#define RELIABILITY_BEST_EFFORT         (1)
#define RELIABILITY_RELIABLE            (2)

/* Destination Order */
#define BY_RECEPTION_TIMESTAMP          (0)
#define BY_SOURCE_TIMESTAMP             (1)



/* Participant message data kind */
#define PARTICIPANT_MESSAGE_DATA_KIND_UNKNOWN (0x00000000)
#define PARTICIPANT_MESSAGE_DATA_KIND_AUTOMATIC_LIVELINESS_UPDATE (0x00000001)
#define PARTICIPANT_MESSAGE_DATA_KIND_MANUAL_LIVELINESS_UPDATE (0x00000002)



#ifdef __cplusplus
} /* extern "C"*/
#endif
            
#endif /* _TYPEDEFS_DEFINES_RTPS2_H */
