/* ti-smartrf.c
 * Routines for opening .psd capture files created by
 * Texas Instruments Packet Sniffer (SmartRF Studio)
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

#include <glib.h>
#include <string.h>
#include "wtap.h"
#include "wtap-int.h"
#include <wsutil/buffer.h>
#include "file_wrappers.h"
#include "ti-smartrf.h"

#define DEBUG0 0

static gboolean ti_smartrf_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset);

static gboolean ti_smartrf_seek_read(wtap *wth, gint64 seek_off,
                                     struct wtap_pkthdr *phdr, 
                                     Buffer *buf,
                                     int *err,
                                     gchar **err_info);

enum {
	VER_UNKNOWN,
	VER_SNIFFER_2420, /* cc2420 sniffer */
	VER_SNIFFER_RFST, /* rf studio, for cc2531 and so on */
};

#define SNIFFER_2420_HEADER_SIZE	8
#define SNIFFER_2420_RECORD_SIZE	(4 + 128)
#define SNIFFER_RFST_HEADER_SIZE	0
#define SNIFFER_RFST_RECORD_SIZE	(1 + 4 + 8 + 138)
#define MAX_SIZE			SNIFFER_RFST_RECORD_SIZE

struct psd_priv {
	int record_size;
	int payload_offset;
	int time_size;
	int time_offset;
	int time_scale;
	int ver;
};

static gboolean read_record(
	struct psd_priv *priv,
	FILE_T fh,
	guchar *data,
	int *len,
	guint64 *usec,
	int *err,
	gchar **err_info _U_
)
{
	int sz = priv->record_size;

#if DEBUG0
        printf("%s: %d sz %d\n", __func__, 0, sz);
#endif

	if (file_read(data, sz, fh) < sz) {
		*err = file_error(fh, err_info);
		return FALSE;
	}

#if DEBUG0
    printf("%s: %d\n", __func__, 1);
#endif

	if (usec) {
		*usec = 0;
		memcpy(usec, data + priv->time_offset, priv->time_size);
		*usec /= priv->time_scale;
	}

#if DEBUG0
    printf("%s: %d\n", __func__, 2);
#endif

	*len = data[priv->payload_offset - 1];
	if ((2 == priv->ver) && (0 == (data[0] & 1))) /* frame len without fcs */
		*len += 2;
#if DEBUG0
        printf("%s: payload_offset %d, len %d \n",__func__, priv->payload_offset, (*len));
#endif


	if (*len < 3 || *len >= 128)
		return FALSE;
#if DEBUG0
    printf("%s: %d\n", __func__, 3);
#endif


	return TRUE;
}

static gint64 get_file_size(wtap *wth)
{
	ws_statb64 statb;
	int err;
	if (!wth->random_fh)
		return -1;
	if (file_fstat(wth->random_fh, &statb, &err) < 0)
		return -1;
	return statb.st_size;
}

int ti_smartrf_open(wtap *wth, int *err, gchar **err_info)
{
	gint64 rec_count = 0, file_size;
	struct psd_priv *priv;

        (void) err_info;

#if DEBUG0
        printf("%s: %d\n", __func__, 0);
#endif


	if (file_read(&rec_count, 4, wth->fh) < 4) {
            return WTAP_OPEN_NOT_MINE;
        }

	file_size = get_file_size(wth);
	if (file_size <= 0) {
            return WTAP_OPEN_NOT_MINE;
        }

	priv = (struct psd_priv *)g_malloc0(sizeof(struct psd_priv));

	/* check and tune to cc2420 file format */
	if (rec_count * SNIFFER_2420_RECORD_SIZE + SNIFFER_2420_HEADER_SIZE == file_size) {
#if DEBUG0
            printf("CC2420 format.\n");
#endif

		priv->record_size = SNIFFER_2420_RECORD_SIZE;
		priv->payload_offset = 1;
		priv->time_size = 4;
		priv->time_offset = 128;
		priv->time_scale = 1;
		priv->ver = 1;
		file_seek(wth->fh, 8, SEEK_SET, err);
		if (*err < 0) {
                    return WTAP_OPEN_ERROR;
                }
	}

	/* check and tune to 2531 and other rf studio file formats */
	if (0 == (file_size % SNIFFER_RFST_RECORD_SIZE)) {
#if DEBUG0
            printf("CC2531 format.\n");
#endif

		priv->record_size = SNIFFER_RFST_RECORD_SIZE;
		priv->payload_offset = 14;
		priv->time_size = 8;
		priv->time_offset = 5;
		priv->time_scale = 32; /* This is 24 only for cc2520 sniffer files */
		                       /* TI asks about device on opening, this is only reason */
		priv->ver = 2;
		file_seek(wth->fh, 0, SEEK_SET, err);
	}

	if (!priv->ver) {
		g_free(priv);
		return WTAP_OPEN_NOT_MINE;
	}

	wth->priv = priv;

	/* set up the pointers to the handlers for this file type */
	wth->subtype_read = ti_smartrf_read;
	wth->subtype_seek_read = ti_smartrf_seek_read;

	/* set up for file type */
	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_TI_SMARTRF;
	wth->file_encap = WTAP_ENCAP_IEEE802_15_4;
	wth->file_tsprec = WTAP_TSPREC_USEC;
        wth->snapshot_length = 0;

	return WTAP_OPEN_MINE;
}

/* Read the capture file sequentially
 * Wireshark scans the file with sequential reads during preview and initial display. */
static gboolean
ti_smartrf_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset) 
{
	struct psd_priv *priv = (struct psd_priv *)wth->priv;
	guchar  data[MAX_SIZE];
	guint64 usecs;
	int     len;
        unsigned char *p;

	*data_offset = file_tell(wth->fh);

#if DEBUG0
        printf("%s: %d\n", __func__, 0);
#endif

	if (!read_record(priv, wth->fh, data, &len, &usecs, err, err_info))
		return FALSE;

        wth->phdr.rec_type = REC_TYPE_PACKET;
	wth->phdr.presence_flags = WTAP_HAS_TS;
	wth->phdr.ts.nsecs = usecs % 1000000 * 1000;
	wth->phdr.ts.secs = (time_t)(usecs / 1000000);
	wth->phdr.len = len;
	wth->phdr.caplen = len;
	ws_buffer_assure_space(wth->frame_buffer, len);
        p = ws_buffer_start_ptr(wth->frame_buffer);
	memcpy(p, data + priv->payload_offset, len);
#if DEBUG0
        printf("%s: %02x %02x %02x \n", __func__, p[0], p[1], p[2]);
#endif


	return TRUE;
}

/* Read the capture file randomly
 * Wireshark opens the capture file for random access when displaying user-selected packets */
static gboolean
ti_smartrf_seek_read(wtap *wth, gint64 seek_off, 
                     struct wtap_pkthdr *phdr, 
                     Buffer *buf, 
                     int *err, 
                     gchar **err_info)  
{
    struct psd_priv *priv = (struct psd_priv *)wth->priv;
    guchar  data[MAX_SIZE];
    guint64 usecs;
    int     len;

#if DEBUG0
    printf("%s: %d\n", __func__, 0);
#endif

    
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) < 0) {
        *err = file_error(wth->random_fh, err_info);
        return FALSE;
    }
    
    if (!read_record(priv, wth->random_fh, data, &len, &usecs, err, err_info))
        return FALSE;

    phdr->rec_type = REC_TYPE_PACKET;
    phdr->presence_flags = WTAP_HAS_TS;
    phdr->ts.nsecs = usecs % 1000000 * 1000;
    phdr->ts.secs = (time_t)(usecs / 1000000);
    phdr->len = len;
    phdr->caplen = len;

    ws_buffer_assure_space(buf, len);
    if (!memcpy(ws_buffer_start_ptr(buf), data + priv->payload_offset, len)) 
        return FALSE;
    

    return TRUE;
}

/* End file */
