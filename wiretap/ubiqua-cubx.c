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

static gboolean ubiqua_cubx_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset);

static gboolean ubiqua_cubx_seek_read(wtap *wth, gint64 seek_off,
                                      struct wtap_pkthdr *phdr,
                                      Buffer *buf,
                                      int *err,
                                      gchar **err_info);

struct cubx_priv {
	sqlite3 *db;
	sqlite3_stmt *stmt;
	int step_result;
};

/* Open a file and determine if it's a ubiqua file */
int ubiqua_cubx_open(wtap *wth, int *err, gchar **err_info)
{
	struct cubx_priv *priv;
	char buf[32];
	const char *sql = "SELECT id,Raw,UnixTimeStamp,LinkQualityDBm FROM Packets ORDER BY id";
        (void) err_info;

	if (file_read(&buf, 15, wth->fh) < 15)
            goto exit_not_cubx;

	if (strncmp(buf, "SQLite format 3", 15))
            goto exit_not_cubx;

	priv = (struct cubx_priv *)g_malloc(sizeof(struct cubx_priv));

	sqlite3_open_v2(wth->filename, &priv->db, SQLITE_OPEN_URI | SQLITE_OPEN_READONLY, NULL);
	if (SQLITE_OK != sqlite3_errcode(priv->db))
		goto exit_free_priv;

	if (SQLITE_OK != sqlite3_prepare_v2(priv->db, sql, -1, &priv->stmt, 0))
		goto exit_close;

	priv->step_result = sqlite3_step(priv->stmt);
	if (SQLITE_ROW != priv->step_result) {
		sqlite3_finalize(priv->stmt);
		goto exit_close;
	}

	wth->priv = priv;
	file_seek(wth->fh, 0, SEEK_SET, err);

	/* set up the pointers to the handlers for this file type */
	wth->subtype_read = ubiqua_cubx_read;
	wth->subtype_seek_read = ubiqua_cubx_seek_read;

	/* set up for file type */
	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_UBIQUA_CUBX;
	wth->file_encap = WTAP_ENCAP_IEEE802_15_4;
	wth->file_tsprec = WTAP_TSPREC_USEC;
        
	return WTAP_OPEN_MINE; /* it's a Daintree file */

exit_close:
	sqlite3_close(priv->db);
exit_free_priv:
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
		frame[wth->phdr.caplen - 2] = sqlite3_column_int(priv->stmt, 3);
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
	sqlite3_stmt *stmt;
	const char *sql_t = "SELECT id,Raw,UnixTimeStamp,LinkQualityDBm FROM Packets WHERE id=%d";
	char sql[64];
        int len;
        uint8_t *frame;
        double timestamp;

	snprintf(sql, sizeof(sql), sql_t, seek_off);

	if (SQLITE_OK != sqlite3_prepare_v2(priv->db, sql, -1, &stmt, 0)) {
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
	timestamp = sqlite3_column_double(priv->stmt, 2);
	phdr->presence_flags = WTAP_HAS_TS;
	phdr->ts.secs = timestamp;
	phdr->ts.nsecs = 1000000000ul * (timestamp - wth->phdr.ts.secs);
	phdr->len = len;
	phdr->caplen = len;

	ws_buffer_assure_space(buf, len);
	frame = ws_buffer_start_ptr(buf);
	memcpy(frame, sqlite3_column_blob(priv->stmt, 1), len);

	if (len >= 2) {
		frame[phdr->caplen - 2] = sqlite3_column_int(priv->stmt, 3);
	}

	sqlite3_finalize(stmt);
	return TRUE;
}

#endif

/* End file */
