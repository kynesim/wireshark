/* ember-isd.c
 * Routines for opening .isd capture files created by
 * Ember InSight Desktop
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
#if HAVE_ZZIPLIB


#include <glib.h>
#include <string.h>
#include <stdint.h>
#include "wtap.h"
#include "wtap-int.h"
#include <wsutil/buffer.h>
#include "file_wrappers.h"
#include "ember-isd.h"

#undef _FILE_OFFSET_BITS
#undef _LARGE_FILES
#include <zzip/lib.h>

static gboolean ember_isd_read(wtap *wth, int *err, gchar **err_info,
	gint64 *data_offset);

static gboolean ember_isd_seek_read(wtap *wth, gint64 seek_off,
                                    struct wtap_pkthdr *phdr,
                                    Buffer *buf,
                                    int *err,
                                    gchar **err_info);
struct isd_priv {
	ZZIP_FILE *f;
	char read_buffer[1024];
	char packet_buffer[130];
	int  buf_len;
	int  cur_offset;
};

static uint16_t update_crc16(uint16_t crc, uint8_t c)
{
	int i;
	crc ^= c;
	for (i = 0; i < 8; i++)
		if (crc & 1)
			crc = (crc >> 1) ^ 0x8408;
		else
			crc >>= 1;
	return crc;
}

static void pack_crc_lqi_rssi(uint8_t *buffer, int len, int lqi, int rssi)
{
	int i;
	uint16_t crc = 0;

	for(i = 0; i < len; i++)
		crc = update_crc16(crc, buffer[i]);

	if (len >= 2) {
		buffer[len - 2] = rssi;
		buffer[len - 1] = (lqi & 127) | (crc ? 0 : 0x80);
	}
}

static int prepare_packet_buffer(char *s, int *length, uint8_t *buffer)
{
	uint8_t *start_buffer = buffer;
	int len, index = 0, data, lqi = 255, rssi = 255;

	if (sscanf(s + index, "%02x", &len) < 1)
		return -1;

	if (len >= 128)
		return -1;

	index += 2;
	*length = len;

	while (len--) {
		if (s[index] != ' ')
			return -1;
		index++;
		if (sscanf(s + index, "%02x", &data) < 1)
			return -1;
		index+=2;
		*buffer++ = data;
	}

	/* optionally we may have lqi and rssi here */
	index++; /* skip last space */
	if (sscanf(s + index, "%02x", &data) < 1) /* lqi or status */
		return -1;
	index+=2;

	if (s[index] == ']') { /* it was not lqi, but status */
		if (0 == (data & 1)) /* flag for lqi, rssi */
			return -1;
	} else {
		lqi = data;
		index++;
		if (sscanf(s + index, "%02x", &rssi) < 1)
			return -1;
		index+=2;

		index++;
		if (sscanf(s + index, "%02x", &data) < 1) /* status */
			return -1;
		index+=2;

		if (s[index++] != ']' || (data & 1))
			return -1;
	}

	pack_crc_lqi_rssi(start_buffer, *length, lqi, rssi);

	return 0;
}

/* skip string content until c char, then skip c and return offset */
static void next_after(const char *s, int *index, char c)
{
	while (s[*index] && c != s[*index])
		(*index)++;
	while (s[*index] && c == s[*index])
		(*index)++;
}

/* returns 0 if it is not a packet (comment, uart packet)
   returns -1 if unknown format
   otherwise returns offset of data */
static int parse_packet(char *s, uint64_t *time, int *length, uint8_t *buffer)
{
	int index = 0, ret;
	char tmp[16];
        long long unsigned int ttime;

	if (s[index] == '#')
		return 0;

	if (s[index++] != '[')
		return -1;

	sscanf(s + index, "%llu", &ttime);
        /* Stop gcc complaining ... */
        *time = ttime;
	next_after(s, &index, ' ');
	next_after(s, &index, ' ');
	next_after(s, &index, ' ');

	sscanf(s + index, "%15s", tmp);
	if (strcmp(tmp, "Packet"))
		return 0;

	next_after(s, &index, ']');
	next_after(s, &index, '[');
	next_after(s, &index, ']');
	next_after(s, &index, '[');

	ret = index;

	if (prepare_packet_buffer(s + index, length, buffer) < 0)
		ret = -1;

	return ret;
}

/* returns offset of packet, 0 eof or no data, -1 on error packer or file read error */
static int try_read_packet(struct isd_priv *priv, uint64_t *time, int *length, uint8_t *buffer)
{
	char *newline;
	int ret;

	newline = (char*)memchr(priv->read_buffer, '\n', priv->buf_len);
	if (newline) {
		int str_len = ++newline - priv->read_buffer;
		priv->read_buffer[str_len - 1] = 0;
		if (priv->read_buffer[str_len - 2] == '\r')
			priv->read_buffer[str_len - 2] = 0;
		ret = parse_packet(priv->read_buffer, time, length, buffer);
		if (ret > 0)
			ret += priv->cur_offset;
		priv->buf_len -= str_len;
		memmove(priv->read_buffer, newline, priv->buf_len);
		priv->cur_offset += str_len;
	} else {
		if (priv->buf_len == sizeof(priv->read_buffer))
			return -1;
		ret = zzip_file_read(
			priv->f,
			priv->read_buffer + priv->buf_len,
			sizeof(priv->read_buffer) - priv->buf_len
		);
		if (ret == 0 && priv->buf_len) /* no newline at eof */
			ret = -1; /* mark as error for this type of files */
		if (ret > 0) {
			priv->buf_len += ret;
			ret = 0;
		}
		return ret; 
	}

	return ret;
}

/* returns offset of packet, 0 if eof, -1 on error packer or file read error */
static int read_packet(struct isd_priv *priv, uint64_t *time, int *length, uint8_t *buffer)
{
	int ret;
	do {
		ret = try_read_packet(priv, time, length, buffer);
	} while (!ret && priv->buf_len);
	return ret;
}

/* Open a file and determine if it's a ember file */
wtap_open_return_val ember_isd_open(wtap *wth, int *err, gchar **err_info)
{
	struct isd_priv *priv;
	gchar *str;
	char buf[2];
	static zzip_strings_t my_ext[] = { "", 0 };
        (void) err_info;

	if (!wth->filename)
		goto exit_not_isd;

	str = g_ascii_strup(wth->filename, -1);
	if (!g_str_has_suffix(str, ".ISD")) {
		g_free(str);
		goto exit_not_isd;
	}
	g_free(str);

	if (file_read(&buf, 2, wth->fh) < 2)
		goto exit_not_isd;

	if (strncmp(buf, "PK", 2))
		goto exit_not_isd;

	priv = (struct isd_priv *)g_malloc(sizeof(struct isd_priv));
	str = g_strdup_printf("%s/event.log", wth->filename);
	priv->f = zzip_open_ext_io(str, O_RDONLY, ZZIP_ONLYZIP, my_ext, 0);
	g_free(str);
	if (!priv->f)
		goto exit_free_priv;

	priv->buf_len = 0;
	priv->cur_offset = 0;

	wth->priv = priv;
	file_seek(wth->fh, 0, SEEK_SET, err);

	/* set up the pointers to the handlers for this file type */
	wth->subtype_read = ember_isd_read;
	wth->subtype_seek_read = ember_isd_seek_read;

	/* set up for file type */
	wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_EMBER_ISD;
	wth->file_encap = WTAP_ENCAP_IEEE802_15_4;
	wth->file_tsprec = WTAP_TSPREC_USEC;

	return WTAP_OPEN_MINE; /* it's our file */

exit_free_priv:
	g_free(priv);
exit_not_isd:
	return WTAP_OPEN_NOT_MINE;
}

/* Read the capture file sequentially
 * Wireshark scans the file with sequential reads during preview and initial display. */
static gboolean
ember_isd_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
	struct  isd_priv *priv = (struct isd_priv *)wth->priv;
	uint64_t timestamp;
	int length, ret;

	ret = read_packet(priv, &timestamp, &length, priv->packet_buffer);

	if (ret < 0) {
		*err = WTAP_ERR_UNSUPPORTED;
		*err_info = g_strdup_printf("ember-isd: error while parsing data");
	}

	if (ret <= 0)
		return FALSE;

	*data_offset = ret;

	wth->phdr.presence_flags = WTAP_HAS_TS;
	wth->phdr.ts.secs = timestamp / 1000000;
	wth->phdr.ts.nsecs = 1000ul * (timestamp % 1000000);
	wth->phdr.len = length;
	wth->phdr.caplen = length;

	ws_buffer_assure_space(wth->frame_buffer, length);
	memcpy(ws_buffer_start_ptr(wth->frame_buffer), priv->packet_buffer, length);

	return TRUE;
}

/* Read the capture file randomly
 * Wireshark opens the capture file for random access when displaying user-selected packets */
static gboolean ember_isd_seek_read(wtap *wth, gint64 seek_off,
                                    struct wtap_pkthdr *phdr,
                                    Buffer *buf,
                                    int *err,
                                    gchar **err_info)
{
    struct isd_priv *priv = (struct isd_priv *)wth->priv;
    int len;
    int ret;
    uint64_t timestamp;
    int length;

    zzip_seek(priv->f, seek_off, SEEK_SET);
    zzip_file_read(priv->f, priv->read_buffer, 3);
    sscanf(priv->read_buffer, "%02x", &len);
    zzip_file_read(priv->f, priv->read_buffer + 3, len * 3 + 9);
    
    if (prepare_packet_buffer(priv->read_buffer, &len, priv->packet_buffer) < 0) {
        *err = WTAP_ERR_UNSUPPORTED;
        *err_info = g_strdup_printf("ember-isd: error while parsing data");
        return FALSE;
    }

    ret = read_packet(priv, &timestamp, &length, priv->packet_buffer);
    if (ret < 0) {
        (*err) = WTAP_ERR_UNSUPPORTED;
        (*err_info) = g_strdup_printf("ember-isd: error whilst parsing data after seek");
    }
    if (ret <= 0) { 
        return FALSE; 
    }

    phdr->presence_flags = WTAP_HAS_TS;
    phdr->ts.secs = timestamp / 1000000;
    phdr->ts.nsecs = 1000ul * (timestamp % 1000000);
    wth->phdr.len = length;
    wth->phdr.caplen = length;

    ws_buffer_assure_space(buf, length);
    memcpy(ws_buffer_start_ptr(buf), priv->packet_buffer, length);

    return TRUE;
}
#endif

