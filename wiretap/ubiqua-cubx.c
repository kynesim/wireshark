/* ubiqua-cubx.c
 * Routines for opening .cubx capture files created by
 * Ubiqua Protocol Analyzer
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"
#if HAVE_SQLITE3

#include <glib.h>
#include <string.h>
#include <stdint.h>
#include "wtap.h"
#include "wtap-int.h"
#include <wsutil/buffer.h>
#include "file_wrappers.h"
#include "ubiqua-cubx.h"
#include "sqlite3.h"

#define DEBUG0 0

/* Ugh! */
extern gboolean zbee_sec_load_ext_keys( gchar ** keys,
                                        const guint * key_type,
                                        guint nr_keys );

static gboolean ubiqua_cubx_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset);

static gboolean ubiqua_cubx_seek_read(wtap *wth, gint64 seek_off,
                                      struct wtap_pkthdr *phdr,
                                      Buffer *buf,
                                      int *err,
                                      gchar **err_info);

/* There are two versions of CUBX file; the newer (which we call v1) contains a Packets table like
 * 
 * CREATE TABLE [Packets] ([Id] INTEGER PRIMARY KEY AUTOINCREMENT, [Raw] BLOB, [Protocol] TEXT, [Length] TEXT, [Channel] TEXT, [Comment] TEXT, [TimeStampValue] TEXT, [UnixTimeStamp] TEXT, [UTCDateTime] TEXT, [TimeDeltaValue] TEXT, [LongAddr] TEXT, [LinkQuality] TEXT, [LinkQualityDBm] TEXT, [Metadata] TEXT);
 *
 *  .. and the older (v0) contains 
 *
 *  CREATE TABLE [Packets] ([Id] Integer PRIMARY KEY AUTOINCREMENT, [Raw] BLOB, [Stack] INTEGER, [Channel] INTEGER, [Timestamp] REAL, [TimeDelta] REAL, [LQI] INTEGER, [RSSI] INTEGER, [Comment] TEXT);
 * 
 * Annoyingly, Ubiqua has the ability to transport security keys separately. We may one day arrange
 * to load them, but for now we simply print them in the hope that the user can load them into
 * the preferences explicitly - we have no such access.
 */
struct cubx_priv {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int step_result;
    /* Version is 0 for v0 files, 1 for v1 files */
    int version;
};

static const char *sql_order_by_id[] = {
    "SELECT id,Raw,UnixTimeStamp,LinkQualityDBm FROM Packets ORDER BY id",
     "SELECT id,Raw,Timestamp,LQI FROM Packets ORDER BY id" 
};     

static const char *sql_find_id[] = { 
    "SELECT id,Raw,UnixTimeStamp,LinkQualityDBm FROM Packets WHERE id=%d",
    "SELECT id,Raw,Timestamp,LQI FROM Packets WHERE id=%d" 
};

static const char *sql_count_keys[] = { 
    "SELECT COUNT(*) from Keys",
    "SELECT COUNT(*) from Keys" 
};

static const char *sql_list_keys[] = { 
    "SELECT Key,Type from Keys",
    "SELECT Key,Type from Keys"
};

static const char *sql_get_version="SELECT Value from Metadata where Key='FileFormat'";

/* Open a file and determine if it's a ubiqua file */
int ubiqua_cubx_open(wtap *wth, int *err, gchar **err_info)
{
	struct cubx_priv *priv;
	char buf[32];
        sqlite3_stmt *vsn_stmt = NULL;
        sqlite3_stmt *key_stmt = NULL;
        int nr_keys = 0;
        int i;
        gchar **keys = NULL;
        guint *key_types = NULL;
        (void) err_info;

	if (file_read(&buf, 15, wth->fh) < 15)
            goto exit_not_cubx;


	if (strncmp(buf, "SQLite format 3", 15))
            goto exit_not_cubx;

	priv = (struct cubx_priv *)g_malloc(sizeof(struct cubx_priv));

	sqlite3_open_v2(wth->filename, &priv->db, SQLITE_OPEN_URI | SQLITE_OPEN_READONLY, NULL);
	if (SQLITE_OK != sqlite3_errcode(priv->db))
		goto exit_free_priv;

        /* Now, what version do we have? */
        if (SQLITE_OK == sqlite3_prepare_v2(priv->db, sql_get_version, -1, &vsn_stmt, 0 )) { 
            int vsn;

            if (SQLITE_ROW != sqlite3_step(vsn_stmt)) {
#if DEBUG0
                printf("(no version row in table)\n");
#endif

                vsn = 0;
            } else {
                vsn =sqlite3_column_int(vsn_stmt, 0); 
            }
            /* Check for version 1 */
#if DEBUG0
            printf("Version %d file.\n", vsn);
#endif

            priv->version = vsn;
            if (vsn != 0 && vsn != 1) { 
                // we don't understand it.
                (*err) = WTAP_OPEN_NOT_MINE;
                (*err_info) = g_strdup_printf("ubiqua-cubx: This file is a CUBX with unrecognised version %d", vsn);
                goto exit_free_priv;
            }
        } else {
            /* Otherwise, this is a version 0 file .. */
            priv->version = 0;
        }
       
        /* Now, this is extremely nasty - we forcibly load any keys we find in the
         * file into a private key set we share with packet-zbee-security 
         */
        if (SQLITE_OK != sqlite3_prepare_v2(priv->db, sql_count_keys[priv->version], -1, &key_stmt, 0)) {
#if DEBUG0
            printf("Cannot prepare keys\n");
#endif
            goto exit_close;
        }
        if (SQLITE_ROW != sqlite3_step(key_stmt))  {
#if DEBUG0
            printf("Cannot count keys\n");
#endif

            goto exit_close;
        }
        nr_keys = sqlite3_column_int(key_stmt, 0);
#if DEBUG0
        printf("%d keys to load.\n", nr_keys);
#endif
        sqlite3_finalize(key_stmt); key_stmt = NULL;

        /* Now load them */
        if (SQLITE_OK != sqlite3_prepare_v2(priv->db, sql_list_keys[priv->version], -1, &key_stmt, 0)) {
#if DEBUG0
            printf("Cannot list keys prep\n");
#endif

            goto exit_close;
        }
        keys = (gchar **)g_malloc( nr_keys * sizeof(gchar *));
        memset(keys, '\0', nr_keys * sizeof(gchar  *));
        key_types = (guint *)g_malloc( nr_keys * sizeof(guint) );
        for (i = 0; i < nr_keys; ++i) {
            const gchar *type;
            gchar *p;

            if (SQLITE_ROW != sqlite3_step(key_stmt)) {
#if DEBUG0
                printf("Cannot step key %d\n", i);
#endif

                goto exit_close;
            }

            type = sqlite3_column_text(key_stmt, 1);
            if (!strcmp(type, "LinkKey")) { 
                key_types[i] = 0;
            } else {
                /* Must be network */
                key_types[i] = 1;
            }
            
           keys[i] = (gchar *)g_malloc(512);
            p = keys[i]; 
            if (priv->version == 1) { 
                /*  Version 1 keys are binary - need to convert these to hex. */
                const unsigned char *q = (const unsigned char *)sqlite3_column_blob(key_stmt, 0);
                int nr = sqlite3_column_bytes(key_stmt, 0);
                int j;
                for (j = 0;j < nr; ++j, ++q) {
                    if (j) { 
                        p += sprintf(p, ":%02x", *q);
                    } else {
                        p += sprintf(p, "%02x", *q);
                    }
                }
            } else {
                /* Version 0 keys are hex - can just be used, but we do need to reformat
                 *  first.
                 */
                int nr = sqlite3_column_bytes(key_stmt, 0);
                const unsigned char * q = (const unsigned char *)sqlite3_column_blob(key_stmt, 0);
                int j;

                /* If we run over the end of q, all that happens is we copy a NUL */
                /* Skip the initial 0x */
                q += 2;
                for (j =2; j < nr; j += 2) { 
                    if (j > 2) { 
                        /* Separator */
                        *p++ = ':';
                    }
                    /* Hex digits */
                    *p++ = *q++;
                    *p++ = *q++;
                }
                /* Terminator */
                *p = '\0';
            }
#if DEBUG0
            printf("Got a key: type = %d, key = %s \n", key_types[i], 
                   keys[i]);
#endif

        }
        {
            wtap_zbee_ext_keys_fn_t fn_p = wtap_get_zbee_ext_keys();
            if (fn_p) { 
#if DEBUG0
                printf("Registering keys.\n");
#endif

                fn_p( keys, key_types, nr_keys);
            } else {
#if DEBUG0
                printf("Cannot register keys - function not present.\n");
#endif
            }
        }

        /* TODO: do this more elegantly */
        if (keys) { 
            for (i =0 ;i < nr_keys; ++i) { 
                g_free(keys[i]);
            }
            g_free(keys);
        }
        if (key_types) {  g_free(key_types); }
          
        if (SQLITE_OK != sqlite3_prepare_v2(priv->db, sql_order_by_id[priv->version], -1, &priv->stmt, 0))
            goto exit_close;
        
        priv->step_result = sqlite3_step(priv->stmt);
        if (SQLITE_ROW != priv->step_result) {
            sqlite3_finalize(priv->stmt);
            goto exit_close;
        }
        /* set up the pointers to the handlers for this file type */
        wth->subtype_read = ubiqua_cubx_read;
        wth->subtype_seek_read = ubiqua_cubx_seek_read;

        wth->priv = priv;
        file_seek(wth->fh, 0, SEEK_SET, err);
        /* set up for file type */
        wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_UBIQUA_CUBX;
        wth->file_encap = WTAP_ENCAP_IEEE802_15_4;
        wth->file_tsprec = WTAP_TSPREC_USEC;

        return WTAP_OPEN_MINE; /* it's a CUBX file */
exit_close:
        if (keys) { 
            for (i =0 ;i < nr_keys; ++i) { 
                g_free(keys[i]);
            }
            g_free(keys);
        }
        if (key_types) {  g_free(key_types); }
        if (priv->stmt) { sqlite3_finalize(priv->stmt); }
        if (vsn_stmt) { sqlite3_finalize(vsn_stmt); }
        if (key_stmt) { sqlite3_finalize(key_stmt); }
	sqlite3_close(priv->db);
exit_free_priv:
        wth->priv = NULL;
	g_free(priv);
exit_not_cubx:
	return WTAP_OPEN_NOT_MINE;
}

/* Read the capture file sequentially
 * Wireshark scans the file with sequential reads during preview and initial display. */
static gboolean
ubiqua_cubx_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	struct  cubx_priv *priv = (struct cubx_priv *)wth->priv;
	double timestamp;
	int len;
	uint8_t* frame;


	if (SQLITE_ROW != priv->step_result) {
		sqlite3_finalize(priv->stmt);
		//how to say no error ?
		*err = file_error(wth->fh, err_info);
		return FALSE;
	}

	*data_offset = sqlite3_column_int(priv->stmt, 0);

	timestamp = sqlite3_column_double(priv->stmt, 2);
	len = sqlite3_column_bytes(priv->stmt, 1);
	wth->phdr.presence_flags = WTAP_HAS_TS;
	wth->phdr.ts.secs = timestamp;
	wth->phdr.ts.nsecs = 1000000000ul * (timestamp - wth->phdr.ts.secs);
	wth->phdr.len = len;
	wth->phdr.caplen = len;

	ws_buffer_assure_space(wth->frame_buffer, len);
	frame = ws_buffer_start_ptr(wth->frame_buffer);
	memcpy(frame, sqlite3_column_blob(priv->stmt, 1), len);

	if (len >= 2) {
		frame[len - 2] = sqlite3_column_int(priv->stmt, 3);
	}

	priv->step_result = sqlite3_step(priv->stmt);
	return TRUE;
}

/* Read the capture file randomly 
 * Wireshark opens the capture file for random access when displaying user-selected packets */
static gboolean
ubiqua_cubx_seek_read(wtap *wth, gint64 seek_off, struct wtap_pkthdr *phdr,
                      Buffer *buf, int *err, gchar **err_info) 
{
	struct cubx_priv *priv = (struct cubx_priv *)wth->priv;
	sqlite3_stmt *stmt = NULL;
	char sql[128];
        int len;
        uint8_t *frame;
        double timestamp;
        int rv;
        
	snprintf(sql, sizeof(sql), sql_find_id[priv->version], seek_off);
        
        rv = sqlite3_prepare_v2(priv->db, sql, -1, &stmt, 0);
	if (SQLITE_OK != rv) { 
            *err = WTAP_ERR_INTERNAL;
            *err_info = g_strdup_printf("ubiqua-cubx: bad request to database");
            return FALSE;
	}

	if (SQLITE_ROW != sqlite3_step(stmt)) {
            *err = WTAP_ERR_SHORT_READ;
            *err_info = g_strdup_printf("ubiqua-cubx: cannot read packet from database");
            sqlite3_finalize(stmt);
            return FALSE;
	}

        len = sqlite3_column_bytes(stmt, 1);
	timestamp = sqlite3_column_double(stmt, 2);
	phdr->presence_flags = WTAP_HAS_TS;
	phdr->ts.secs = timestamp;
	phdr->ts.nsecs = 1000000000ul * (timestamp - wth->phdr.ts.secs);
	phdr->len = len;
	phdr->caplen = len;

	ws_buffer_assure_space(buf, len);
	frame = ws_buffer_start_ptr(buf);
	memcpy(frame, sqlite3_column_blob(stmt, 1), len);

	if (len >= 2) {
		frame[len-2] = sqlite3_column_int(stmt, 3);
	}

	sqlite3_finalize(stmt);
	return TRUE;
}

#endif

/* End file */
