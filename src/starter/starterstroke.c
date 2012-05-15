/*
 * Copyright (C) 2006 Martin Willi
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <credentials/auth_cfg.h>

#include <library.h>
#include <debug.h>

#include <constants.h>
#include <defs.h>

#include <stroke_msg.h>

#include "starterstroke.h"
#include "confread.h"
#include "files.h"

#define IPV4_LEN	 4
#define IPV6_LEN	16

static char* push_string(stroke_msg_t *msg, char *string)
{
	unsigned long string_start = msg->length;

	if (string == NULL || msg->length + strlen(string) >= sizeof(stroke_msg_t))
	{
		return NULL;
	}
	else
	{
		msg->length += strlen(string) + 1;
		strcpy((char*)msg + string_start, string);
		return (char*)string_start;
	}
}

static int send_stroke_msg (stroke_msg_t *msg)
{
	struct sockaddr_un ctl_addr;
	int byte_count;
	char buffer[64];

	ctl_addr.sun_family = AF_UNIX;
	strcpy(ctl_addr.sun_path, CHARON_CTL_FILE);

	/* starter is not called from commandline, and therefore absolutely silent */
	msg->output_verbosity = -1;

	int sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sock < 0)
	{
		DBG1(DBG_APP, "socket() failed: %s", strerror(errno));
		return -1;
	}
	if (connect(sock, (struct sockaddr *)&ctl_addr, offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0)
	{
		DBG1(DBG_APP, "connect(charon_ctl) failed: %s", strerror(errno));
		close(sock);
		return -1;
	}

	/* send message */
	if (write(sock, msg, msg->length) != msg->length)
	{
		DBG1(DBG_APP, "write(charon_ctl) failed: %s", strerror(errno));
		close(sock);
		return -1;
	}
	while ((byte_count = read(sock, buffer, sizeof(buffer)-1)) > 0)
	{
		buffer[byte_count] = '\0';
		DBG1(DBG_APP, "%s", buffer);
	}
	if (byte_count < 0)
	{
		DBG1(DBG_APP, "read() failed: %s", strerror(errno));
	}

	close(sock);
	return 0;
}

static char* connection_name(starter_conn_t *conn)
{
	 /* if connection name is '%auto', create a new name like conn_xxxxx */
	static char buf[32];

	if (streq(conn->name, "%auto"))
	{
		sprintf(buf, "conn_%lu", conn->id);
		return buf;
	}
	return conn->name;
}

static void starter_stroke_add_end(stroke_msg_t *msg, stroke_end_t *msg_end, starter_end_t *conn_end)
{
	msg_end->auth = push_string(msg, conn_end->auth);
	msg_end->auth2 = push_string(msg, conn_end->auth2);
	msg_end->id = push_string(msg, conn_end->id);
	msg_end->id2 = push_string(msg, conn_end->id2);
	msg_end->rsakey = push_string(msg, conn_end->rsakey);
	msg_end->cert = push_string(msg, conn_end->cert);
	msg_end->cert2 = push_string(msg, conn_end->cert2);
	msg_end->cert_policy = push_string(msg, conn_end->cert_policy);
	msg_end->ca = push_string(msg, conn_end->ca);
	msg_end->ca2 = push_string(msg, conn_end->ca2);
	msg_end->groups = push_string(msg, conn_end->groups);
	msg_end->updown = push_string(msg, conn_end->updown);
	if (conn_end->host)
	{
		msg_end->address = push_string(msg, conn_end->host);
	}
	else
	{
		msg_end->address = push_string(msg, "%any");
	}
	msg_end->ikeport = conn_end->ikeport;
	msg_end->subnets = push_string(msg, conn_end->subnet);
	msg_end->sourceip = push_string(msg, conn_end->sourceip);
	msg_end->sourceip_mask = conn_end->sourceip_mask;
	msg_end->sendcert = conn_end->sendcert;
	msg_end->hostaccess = conn_end->hostaccess;
	msg_end->tohost = !conn_end->has_client;
	msg_end->allow_any = conn_end->allow_any;
	msg_end->protocol = conn_end->protocol;
	msg_end->port = conn_end->port;
}

int starter_stroke_add_conn(starter_config_t *cfg, starter_conn_t *conn)
{
	stroke_msg_t msg;

	memset(&msg, 0, sizeof(msg));
	msg.type = STR_ADD_CONN;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.add_conn.version = conn->keyexchange;
	msg.add_conn.name = push_string(&msg, connection_name(conn));
	msg.add_conn.eap_identity = push_string(&msg, conn->eap_identity);
	msg.add_conn.aaa_identity = push_string(&msg, conn->aaa_identity);
	msg.add_conn.xauth_identity = push_string(&msg, conn->xauth_identity);

	msg.add_conn.mode = conn->mode;
	msg.add_conn.proxy_mode = conn->proxy_mode;

	if (!(conn->policy & POLICY_DONT_REKEY))
	{
		msg.add_conn.rekey.reauth = (conn->policy & POLICY_DONT_REAUTH) == LEMPTY;
		msg.add_conn.rekey.ipsec_lifetime = conn->sa_ipsec_life_seconds;
		msg.add_conn.rekey.ike_lifetime = conn->sa_ike_life_seconds;
		msg.add_conn.rekey.margin = conn->sa_rekey_margin;
		msg.add_conn.rekey.life_bytes = conn->sa_ipsec_life_bytes;
		msg.add_conn.rekey.margin_bytes = conn->sa_ipsec_margin_bytes;
		msg.add_conn.rekey.life_packets = conn->sa_ipsec_life_packets;
		msg.add_conn.rekey.margin_packets = conn->sa_ipsec_margin_packets;
		msg.add_conn.rekey.tries = conn->sa_keying_tries;
		msg.add_conn.rekey.fuzz = conn->sa_rekey_fuzz;
	}
	msg.add_conn.mobike = (conn->policy & POLICY_MOBIKE) != 0;
	msg.add_conn.force_encap = (conn->policy & POLICY_FORCE_ENCAP) != 0;
	msg.add_conn.ipcomp = (conn->policy & POLICY_COMPRESS) != 0;
	msg.add_conn.install_policy = conn->install_policy;
	msg.add_conn.aggressive = conn->aggressive;
	msg.add_conn.crl_policy = (crl_policy_t)cfg->setup.strictcrlpolicy;
	msg.add_conn.unique = cfg->setup.uniqueids;
	msg.add_conn.algorithms.ike = push_string(&msg, conn->ike);
	msg.add_conn.algorithms.esp = push_string(&msg, conn->esp);
	msg.add_conn.dpd.delay = conn->dpd_delay;
	msg.add_conn.dpd.timeout = conn->dpd_timeout;
	msg.add_conn.dpd.action = conn->dpd_action;
	msg.add_conn.close_action = conn->close_action;
	msg.add_conn.inactivity = conn->inactivity;
	msg.add_conn.ikeme.mediation = conn->me_mediation;
	msg.add_conn.ikeme.mediated_by = push_string(&msg, conn->me_mediated_by);
	msg.add_conn.ikeme.peerid = push_string(&msg, conn->me_peerid);
	msg.add_conn.reqid = conn->reqid;
	msg.add_conn.mark_in.value = conn->mark_in.value;
	msg.add_conn.mark_in.mask = conn->mark_in.mask;
	msg.add_conn.mark_out.value = conn->mark_out.value;
	msg.add_conn.mark_out.mask = conn->mark_out.mask;
	msg.add_conn.tfc = conn->tfc;

	starter_stroke_add_end(&msg, &msg.add_conn.me, &conn->left);
	starter_stroke_add_end(&msg, &msg.add_conn.other, &conn->right);

	if (!msg.add_conn.me.auth && !msg.add_conn.other.auth &&
		 conn->authby)
	{	/* leftauth/rightauth not set, use legacy options */
		if (streq(conn->authby, "rsa")   || streq(conn->authby, "rsasig")   ||
			streq(conn->authby, "ecdsa") || streq(conn->authby, "ecdsasig") ||
			streq(conn->authby, "pubkey"))
		{
			msg.add_conn.me.auth = push_string(&msg, "pubkey");
			msg.add_conn.other.auth = push_string(&msg, "pubkey");
		}
		else if (streq(conn->authby, "secret") || streq(conn->authby, "psk"))
		{
			msg.add_conn.me.auth = push_string(&msg, "psk");
			msg.add_conn.other.auth = push_string(&msg, "psk");
		}
		else if (streq(conn->authby, "xauthrsasig"))
		{
			msg.add_conn.me.auth = push_string(&msg, "pubkey");
			msg.add_conn.other.auth = push_string(&msg, "pubkey");
			if (conn->policy & POLICY_XAUTH_SERVER)
			{
				msg.add_conn.other.auth2 = push_string(&msg, "xauth");
			}
			else
			{
				msg.add_conn.me.auth2 = push_string(&msg, "xauth");
			}
		}
		else if (streq(conn->authby, "xauthpsk"))
		{
			msg.add_conn.me.auth = push_string(&msg, "psk");
			msg.add_conn.other.auth = push_string(&msg, "psk");
			if (conn->policy & POLICY_XAUTH_SERVER)
			{
				msg.add_conn.other.auth2 = push_string(&msg, "xauth");
			}
			else
			{
				msg.add_conn.me.auth2 = push_string(&msg, "xauth");
			}
		}
	}
	return send_stroke_msg(&msg);
}

int starter_stroke_del_conn(starter_conn_t *conn)
{
	stroke_msg_t msg;

	msg.type = STR_DEL_CONN;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.del_conn.name = push_string(&msg, connection_name(conn));
	return send_stroke_msg(&msg);
}

int starter_stroke_route_conn(starter_conn_t *conn)
{
	stroke_msg_t msg;

	msg.type = STR_ROUTE;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.route.name = push_string(&msg, connection_name(conn));
	return send_stroke_msg(&msg);
}

int starter_stroke_initiate_conn(starter_conn_t *conn)
{
	stroke_msg_t msg;

	msg.type = STR_INITIATE;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.initiate.name = push_string(&msg, connection_name(conn));
	return send_stroke_msg(&msg);
}

int starter_stroke_add_ca(starter_ca_t *ca)
{
	stroke_msg_t msg;

	msg.type = STR_ADD_CA;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.add_ca.name =        push_string(&msg, ca->name);
	msg.add_ca.cacert =      push_string(&msg, ca->cacert);
	msg.add_ca.crluri =      push_string(&msg, ca->crluri);
	msg.add_ca.crluri2 =     push_string(&msg, ca->crluri2);
	msg.add_ca.ocspuri =     push_string(&msg, ca->ocspuri);
	msg.add_ca.ocspuri2 =    push_string(&msg, ca->ocspuri2);
	msg.add_ca.certuribase = push_string(&msg, ca->certuribase);
	return send_stroke_msg(&msg);
}

int starter_stroke_del_ca(starter_ca_t *ca)
{
	stroke_msg_t msg;

	msg.type = STR_DEL_CA;
	msg.length = offsetof(stroke_msg_t, buffer);
	msg.del_ca.name = push_string(&msg, ca->name);
	return send_stroke_msg(&msg);
}

int starter_stroke_configure(starter_config_t *cfg)
{
	stroke_msg_t msg;

	if (cfg->setup.cachecrls)
	{
		msg.type = STR_CONFIG;
		msg.length = offsetof(stroke_msg_t, buffer);
		msg.config.cachecrl = 1;
		return send_stroke_msg(&msg);
	}
	return 0;
}

