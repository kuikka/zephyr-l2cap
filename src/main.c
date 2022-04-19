/* main.c - Application main entry point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/types.h>
#include <stddef.h>
#include <errno.h>
#include <zephyr.h>
#include <sys/printk.h>
#include <stdlib.h>
#include <string.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/conn.h>
#include <bluetooth/uuid.h>
#include <bluetooth/gatt.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/att.h>
#include <sys/byteorder.h>

#include <logging/log.h>
#define LOG_MODULE_NAME l2captest
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

#define DATA_MTU 2000
#define DATA_BUF_SIZE BT_L2CAP_SDU_BUF_SIZE(DATA_MTU)
#define CHANNELS 2

#define PERIPHERAL_NAME	"FOO"

NET_BUF_POOL_FIXED_DEFINE(data_pool, CHANNELS, DATA_BUF_SIZE, 8, NULL);

static struct net_buf *alloc_buf_cb(struct bt_l2cap_chan *chan);
static int recv_cb(struct bt_l2cap_chan *l2cap_chan, struct net_buf *buf);
static void connected_cb(struct bt_l2cap_chan *l2cap_chan);
static void disconnected_cb(struct bt_l2cap_chan *l2cap_chan);

static const struct bt_l2cap_chan_ops l2cap_ops = {
        .alloc_buf      = alloc_buf_cb,
        .recv           = recv_cb,
        .connected      = connected_cb,
        .disconnected   = disconnected_cb,
};

struct bt_l2cap_le_chan le = {
	.chan.ops = &l2cap_ops,
	.rx.mtu = DATA_MTU,
	.rx.mps = 251,
};

static struct bt_conn *default_conn;

static int64_t first = 0;
static int64_t prev = 0;
static uint64_t bytes_revc = 0;

static struct net_buf *alloc_buf_cb(struct bt_l2cap_chan *chan)
{
        return net_buf_alloc(&data_pool, K_FOREVER);
}

static void dump_connection()
{
	struct bt_conn_info info;
	bt_conn_get_info(default_conn, &info);
	LOG_INF("interval=%d, rx_phy=%d, rx_phy=%d, rx_data_len=%d, tx_data_len=%d",
		info.le.interval,
		info.le.phy->rx_phy,
		info.le.phy->tx_phy,
		info.le.data_len->rx_max_len,
		info.le.data_len->tx_max_len
	);
}

static int recv_cb(struct bt_l2cap_chan *l2cap_chan, struct net_buf *buf)
{
		// LOG_INF("Got data: %d", buf->len);
		bytes_revc += buf->len;

		if (first == 0) {
			prev = first = k_uptime_get();
		}

		int64_t now = k_uptime_get();
		float delta = now - prev;
		if (delta >= 1000) {
			delta = now - first;
			float bps = (bytes_revc * 8) / (delta/1000.0);
			LOG_INF("Throughput %d bps", (int) bps);
			prev = now;

			dump_connection();
		}

        return 0;
}

static void connected_cb(struct bt_l2cap_chan *l2cap_chan)
{
        struct bt_conn_info info;

		LOG_INF("CONNECTED!");

        if (!bt_conn_get_info(l2cap_chan->conn, &info)) {
                switch (info.type) {
                case BT_CONN_TYPE_LE:
						LOG_INF("tx.mtu = %d, tx.mps = %d, rx.mtu = %d, rx.mps = %d",
						 le.tx.mtu,
						 le.tx.mps,
						 le.rx.mtu,
						 le.rx.mps);
                        break;
                case BT_CONN_TYPE_BR:
						LOG_INF("WHAT?");
                        break;
                }
        }
}

static void disconnected_cb(struct bt_l2cap_chan *l2cap_chan)
{
        struct bt_conn_info info;

		LOG_INF("Disconnected!");

        if (!bt_conn_get_info(l2cap_chan->conn, &info)) {
                switch (info.type) {
                case BT_CONN_TYPE_LE:
                        break;
                case BT_CONN_TYPE_BR:
                        break;
                }
        }
}



static void start_scan(void);


static char const *memmem(char const *mem, size_t mem_len, char const *sub,
                   size_t sub_len)
{
        int i;

        if (sub_len <= mem_len && sub_len > 0) {
                for (i = 0; i <= mem_len - sub_len; i++) {
                        if (!memcmp(&mem[i], sub, sub_len)) {
                                return &mem[i];
                        }
                }
        }

        return NULL;
}



static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			 struct net_buf_simple *ad)
{
	char addr_str[BT_ADDR_LE_STR_LEN];
	int err;

	if (default_conn) {
		return;
	}

	/* We're only interested in connectable events */
	if (type != BT_GAP_ADV_TYPE_ADV_IND &&
	    type != BT_GAP_ADV_TYPE_ADV_DIRECT_IND) {
		return;
	}

	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));

	if (memmem(ad->data, ad->len, PERIPHERAL_NAME, strlen(PERIPHERAL_NAME)) == NULL) {
		return;
	}

	LOG_INF("Found %s: %s (RSSI %d)\n", PERIPHERAL_NAME, addr_str, rssi);
	LOG_INF("Device found: %s (RSSI %d)\n", addr_str, rssi);

	/* connect only to devices in close proximity */
	if (rssi < -70) {
		return;
	}

	if (bt_le_scan_stop()) {
		return;
	}

	err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN,
				BT_LE_CONN_PARAM_DEFAULT, &default_conn);
	if (err) {
		LOG_INF("Create conn to %s failed (%u)\n", addr_str, err);
		start_scan();
	}
}

static void start_scan(void)
{
	int err;

	/* This demo doesn't require active scan */
	err = bt_le_scan_start(BT_LE_SCAN_PASSIVE, device_found);
	if (err) {
		printk("Scanning failed to start (err %d)\n", err);
		return;
	}

	LOG_INF("Scanning successfully started\n");
}

static void connected(struct bt_conn *conn, uint8_t err)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	if (err) {
		LOG_INF("Failed to connect to %s (%u)\n", addr, err);

		bt_conn_unref(default_conn);
		default_conn = NULL;

		start_scan();
		return;
	}

	if (conn != default_conn) {
		return;
	}

	LOG_INF("Connected: %s", addr);
	dump_connection();

	struct bt_conn_le_data_len_param update = {
		.tx_max_len = BT_GAP_DATA_LEN_MAX/2,
		.tx_max_time = BT_GAP_DATA_TIME_MAX/2
	};

	LOG_INF("Updating data len");
	int ret = bt_conn_le_data_len_update(conn, &update);
	if (ret < 0) {
		LOG_ERR("Data len update failed: %d", ret);
	}

	// bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);

	// ret = bt_l2cap_chan_connect(conn, &le.chan, 0xC0);
	// if (ret < 0) {
	// 	printk("bt_l2cap_chan_connect() failed: %d", ret);
	// }
}

static void data_len_upadted(struct bt_conn *conn,
				    struct bt_conn_le_data_len_info *info)
{
	LOG_INF("Data len updated: rx_max_len=%d, rx_max_time=%d, tx_max_len=%d, tx_max_time=%d",
		info->rx_max_len,
		info->rx_max_time,
		info->tx_max_len,
		info->tx_max_time
	);
}

static void param_updated(struct bt_conn *conn, uint16_t interval,
				 uint16_t latency, uint16_t timeout)
{
	LOG_INF("Params updated interval=%d, latency=%d, timeout=%d",
		interval, latency, timeout);
}

static void phy_updated(struct bt_conn *conn,
			       struct bt_conn_le_phy_info *param)
{
	LOG_INF("PHY updated: TX: %d, RX=%d", param->tx_phy, param->rx_phy);
}

static void disconnected(struct bt_conn *conn, uint8_t reason)
{
	char addr[BT_ADDR_LE_STR_LEN];

	if (conn != default_conn) {
		return;
	}

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_INF("Disconnected: %s (reason 0x%02x)\n", addr, reason);

	bt_conn_unref(default_conn);
	default_conn = NULL;

	start_scan();
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
	.connected = connected,
	.disconnected = disconnected,
	.le_data_len_updated = data_len_upadted,
	.le_param_updated = param_updated,
	.le_phy_updated = phy_updated,
};

void main(void)
{
	int err;

	err = bt_enable(NULL);
	if (err) {
		LOG_INF("Bluetooth init failed (err %d)\n", err);
		return;
	}

	LOG_INF("Bluetooth initialized\n");

	start_scan();
}
