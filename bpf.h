// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __BRIDGER_BPF_H
#define __BRIDGER_BPF_H

extern int bridger_bpf_prog_fd;
extern int bridger_bpf_tx_prog_fd;

int bridger_bpf_init(void);
void bridger_bpf_dev_policy_set(struct device *dev);
void bridger_bpf_flow_upload(struct bridger_flow *flow);
void bridger_bpf_flow_update(struct bridger_flow *flow);
void bridger_bpf_flow_delete(struct bridger_flow *flow);

void bridger_bpf_set_vlan_isolation(uint16_t vid,
				    struct bridger_vlan_isolation *iso);
void bridger_bpf_del_vlan_isolation(uint16_t vid);
int bridger_bpf_get_vlan_isolation(uint16_t vid,
				   struct bridger_vlan_isolation *iso);
void bridger_bpf_set_port_untagged_vlan(uint32_t ifindex, uint16_t vid);
void bridger_bpf_del_port_untagged_vlan(uint32_t ifindex);

#endif
