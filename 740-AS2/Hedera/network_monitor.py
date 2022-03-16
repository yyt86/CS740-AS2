# Copyright (C) 2016 Li Cheng at Beijing University of Posts
# and Telecommunications. www.muzixing.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import division
import copy
from operator import attrgetter
from ryu import cfg
from ryu.base import app_manager
from ryu.base.app_manager import lookup_service_brick
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
import setting
from demand_est import flow 
from demand_est import estimate_demand


CONF = cfg.CONF


class NetworkMonitor(app_manager.RyuApp):
    """
        NetworkMonitor is a Ryu app for collecting traffic information.

    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(NetworkMonitor, self).__init__(*args, **kwargs)
        self.name = 'monitor'
        self.datapaths = {}
        self.port_stats = {}
        self.port_speed = {}
        self.flow_stats = {}
        self.flow_speed = {}
        self.stats = {}
        self.port_features = {}
        self.free_bandwidth = {}
        self.awareness = lookup_service_brick('awareness')
        self.graph = None
        self.capabilities = None
        self.best_paths = None
        self.dpids = []
        self.hosts = []
        self.flows = []

        # Start to green thread to monitor traffic and calculating
        # free bandwidth of links respectively.
        self.monitor_thread = hub.spawn(self._monitor)
        self.save_freebandwidth_thread = hub.spawn(self._save_bw_graph)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
            Record datapath's info
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        """
            Main entry method of monitoring traffic.
        """
        while CONF.weight == 'bw':
            self.stats['flow'] = {}
            self.stats['port'] = {}
            self.dpids = []
            self.flows = []
            self.capabilities = None
            self.best_paths = None
            for dp in self.datapaths.values():
                self.port_features.setdefault(dp.id, {})
                self._request_stats(dp)
                # refresh data.
                
            hub.sleep(setting.MONITOR_PERIOD)
            if self.stats['flow'] or self.stats['port']:
                self.show_stat('flow')
                self.show_stat('port')
                hub.sleep(1)

    def _save_bw_graph(self):
        """
            Save bandwidth data into networkx graph object.
        """
        while CONF.weight == 'bw':
            self.graph = self.create_bw_graph(self.free_bandwidth)
            self.logger.debug("save_freebandwidth")
            hub.sleep(setting.MONITOR_PERIOD)

    def _request_stats(self, datapath):
        """
            Sending request msg to datapath
        """
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def get_min_bw_of_links(self, graph, path, min_bw):
        """
            Getting bandwidth of path. Actually, the mininum bandwidth
            of links is the bandwith, because it is the neck bottle of path.
        """
        _len = len(path)
        if _len > 1:
            minimal_band_width = min_bw
            for i in xrange(_len-1):
                pre, curr = path[i], path[i+1]
                if 'bandwidth' in graph[pre][curr]:
                    bw = graph[pre][curr]['bandwidth']
                    minimal_band_width = min(bw, minimal_band_width)
                else:
                    continue
            return minimal_band_width
        return min_bw

    def get_best_path_by_bw(self, graph, paths):
        """
            Get best path by comparing paths.
        """
        capabilities = {}
        best_paths = copy.deepcopy(paths)

        for src in paths:
            for dst in paths[src]:
                if src == dst:
                    best_paths[src][src] = [src]
                    capabilities.setdefault(src, {src: setting.MAX_CAPACITY})
                    capabilities[src][src] = setting.MAX_CAPACITY
                    continue
                max_bw_of_paths = 0
                best_path = paths[src][dst][0]
                for path in paths[src][dst]:
                    min_bw = setting.MAX_CAPACITY
                    min_bw = self.get_min_bw_of_links(graph, path, min_bw)
                    if min_bw > max_bw_of_paths:
                        max_bw_of_paths = min_bw
                        best_path = path

                best_paths[src][dst] = best_path
                capabilities.setdefault(src, {dst: max_bw_of_paths})
                capabilities[src][dst] = max_bw_of_paths
        self.capabilities = capabilities
        self.best_paths = best_paths
        return capabilities, best_paths

    def create_bw_graph(self, bw_dict):
        """
            Save bandwidth data into networkx graph object.
        """
        try:
            graph = self.awareness.graph
            link_to_port = self.awareness.link_to_port
            for link in link_to_port:
                (src_dpid, dst_dpid) = link
                (src_port, dst_port) = link_to_port[link]
                if src_dpid in bw_dict and dst_dpid in bw_dict:
                    bw_src = bw_dict[src_dpid][src_port]
                    bw_dst = bw_dict[dst_dpid][dst_port]
                    bandwidth = min(bw_src, bw_dst)
                    # add key:value of bandwidth into graph.
                    graph[src_dpid][dst_dpid]['bandwidth'] = bandwidth
                else:
                    graph[src_dpid][dst_dpid]['bandwidth'] = 0
            return graph
        except:
            self.logger.info("Create bw graph exception")
            if self.awareness is None:
                self.awareness = lookup_service_brick('awareness')
            return self.awareness.graph

    def _save_freebandwidth(self, dpid, port_no, speed):
        # Calculate free bandwidth of port and save it.
        port_state = self.port_features.get(dpid).get(port_no)
        if port_state:
            capacity = setting.MAX_CAPACITY  # port_state[2]
            curr_bw = self._get_free_bw(capacity, speed)
            self.free_bandwidth[dpid].setdefault(port_no, None)
            self.free_bandwidth[dpid][port_no] = curr_bw
        else:
            self.logger.info("Fail in getting port state")

    def _save_stats(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        if len(_dict[key]) > length:
            _dict[key].pop(0)

    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / (period)
        else:
            return 0

    def _get_free_bw(self, capacity, speed):
        # BW:Mbit/s
        return max(capacity / 1024 - speed * 8/1024/1024, 0)

    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)

    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """
            Save flow stats reply info into self.flow_stats.
            Calculate flow speed and Save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})
        self.flow_speed.setdefault(dpid, {})
        self.dpids.append(dpid)
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match.get('in_port'),
                                             flow.match.get('ipv4_dst'))):
                        #                      ((flow.priority not in [0, 65535]) and (flow.match.get('ipv4_src')) and (flow.match.get('ipv4_dst')))],
						#    key=lambda flow: (flow.priority, flow.match.get('ipv4_src'), flow.match.get('ipv4_dst'))):
            key = (stat.match['in_port'],  stat.match.get('ipv4_dst'),
                   stat.instructions[0].actions[0].port)
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats[dpid], key, value, 5)

            # Get flow's speed.
            pre = 0
            period = setting.MONITOR_PERIOD
            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])

            speed = self._get_speed(self.flow_stats[dpid][key][-1][1],
                                    pre, period)

            self._save_stats(self.flow_speed[dpid], key, speed, 5)

            # add flows that need to be rescheduled
            if str(dpid).startswith('3'):
                flowDemand = speed * 8.0 / (setting.MAX_CAPACITY * 1024)
                src = stat.match['ipv4_src']
                dst = stat.match['ipv4_dst']
                if flowDemand > 0.1:
                    if src not in self.hosts:
                        self.hosts.append(src)
                    if dst not in self.hosts:
                        self.hosts.append(dst)
                    self.flows.append(flow(src, dst, flowDemand, stat.match, stat.priority))
                    # if not self.pre_GFF_path.has_key((src, dst)):
                    #     self.pre_GFF_path[(src, dst)] = None
        
        if len(self.dpids) == 1.25 * (CONF.fanout ** 2) and self.flows:
            flows = sorted([flow for flow in self.flows], key=lambda flow: (flow.src, flow.dst))
            hosts = sorted(self.hosts)
            estimated_flows = estimate_demand(flows, hosts)
        for flow in estimated_flows:
            if flow.demand > 0.1:
                self.global_first_fit(flow)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
            Save port's stats info
            Calculate port's speed and save it.
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        self.stats['port'][dpid] = body
        self.free_bandwidth.setdefault(dpid, {})

        for stat in sorted(body, key=attrgetter('port_no')):
            port_no = stat.port_no
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                         stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed.
                pre = 0
                period = setting.MONITOR_PERIOD
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self._get_period(tmp[-1][3], tmp[-1][4],
                                              tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][0] + self.port_stats[key][-1][1],
                    pre, period)

                self._save_stats(self.port_speed, key, speed, 5)
                self._save_freebandwidth(dpid, port_no, speed)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        """
            Save port description info.
        """
        msg = ev.msg
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        config_dict = {ofproto.OFPPC_PORT_DOWN: "Down",
                       ofproto.OFPPC_NO_RECV: "No Recv",
                       ofproto.OFPPC_NO_FWD: "No Farward",
                       ofproto.OFPPC_NO_PACKET_IN: "No Packet-in"}

        state_dict = {ofproto.OFPPS_LINK_DOWN: "Down",
                      ofproto.OFPPS_BLOCKED: "Blocked",
                      ofproto.OFPPS_LIVE: "Live"}

        ports = []
        for p in ev.msg.body:
            ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x '
                         'state=0x%08x curr=0x%08x advertised=0x%08x '
                         'supported=0x%08x peer=0x%08x curr_speed=%d '
                         'max_speed=%d' %
                         (p.port_no, p.hw_addr,
                          p.name, p.config,
                          p.state, p.curr, p.advertised,
                          p.supported, p.peer, p.curr_speed,
                          p.max_speed))

            if p.config in config_dict:
                config = config_dict[p.config]
            else:
                config = "up"

            if p.state in state_dict:
                state = state_dict[p.state]
            else:
                state = "up"

            port_feature = (config, state, p.curr_speed)
            self.port_features[dpid][p.port_no] = port_feature

    def install_flow(self, datapaths, link_to_port, path, flow_info):
        '''
            Install flow entries for datapaths.
            path=[dpid1, dpid2, ...]
            flow_info = (eth_type, src_ip, dst_ip, priority)
            self.awareness.access_table = {(sw,port):(ip, mac),}
        '''
        if path is None or len(path) == 0:
            self.logger.info("Path error!")
            return
        in_port = None
        for key in self.awareness.access_table.keys():
            if self.awareness.access_table[key][0] == flow_info[1]:
                in_port = key[1]
        first_dp = datapaths[path[0]]
        out_port = first_dp.ofproto.OFPP_LOCAL
        # Install flow entry for intermediate datapaths.
        for i in xrange(1, int((len(path)-1)/2)):
            port = self.get_port_pair_from_link(link_to_port, path[i-1], path[i])
            port_next = self.get_port_pair_from_link(link_to_port, path[i], path[i+1])
            if port and port_next:
                src_port, dst_port = port[1], port_next[0]
                datapath = datapaths[path[i]]
                self.send_flow_mod(datapath, flow_info, src_port, dst_port)

        # Install flow entry for the first datapath.
        port_pair = self.get_port_pair_from_link(link_to_port, path[0], path[1])
        if port_pair is None:
            self.logger.info("Port not found in first hop.")
            return
        out_port = port_pair[0]
        self.send_flow_mod(first_dp, flow_info, in_port, out_port)

    def get_port_pair_from_link(self, link_to_port, src_dpid, dst_dpid):
        """
            Get port pair of link, so that controller can install flow entry.
            link_to_port = {(src_dpid,dst_dpid):(src_port,dst_port),}
        """
        if (src_dpid, dst_dpid) in link_to_port:
            return link_to_port[(src_dpid, dst_dpid)]
        else:
            self.logger.info("Link from dpid:%s to dpid:%s is not in links" %
                (src_dpid, dst_dpid))
            return None

    def send_flow_mod(self, datapath, flow_info, src_port, dst_port):
        """
            Build flow entry, and send it to datapath.
            flow_info = (eth_type, src_ip, dst_ip, priority)
        """
        parser = datapath.ofproto_parser
        actions = []
        actions.append(parser.OFPActionOutput(dst_port))
        if len(flow_info) == 7:
            if flow_info[-3] == 6:
                if flow_info[-2] == 'src':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=6, tcp_src=flow_info[-1])
                elif flow_info[-2] == 'dst':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=6, tcp_dst=flow_info[-1])
                else:
                    pass
            elif flow_info[-3] == 17:
                if flow_info[-2] == 'src':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=17, udp_src=flow_info[-1])
                elif flow_info[-2] == 'dst':
                    match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2],
                        ip_proto=17, udp_dst=flow_info[-1])
                else:
                    pass
        elif len(flow_info) == 4:
            match = parser.OFPMatch(
                        in_port=src_port, eth_type=flow_info[0],
                        ipv4_src=flow_info[1], ipv4_dst=flow_info[2])
        else:
            pass
        priority = flow_info[3] + 1

        self.add_flow(datapath, priority, match, actions,
                        idle_timeout=15, hard_timeout=60)

    def add_flow(self, dp, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """
            Send a flow entry to datapath.
        """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                idle_timeout=idle_timeout,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        dp.send_msg(mod)
   
    def global_first_fit(self, flow):
        src_dp = self.awareness.get_host_location(flow.src)[0]
        dst_dp = self.awareness.get_host_location(flow.dst)[0]
        paths = self.awareness.shortest_paths.get(src_dp).get(dst_dp)
        first_path = None
        for p in paths:
            flag = True
            for i in xrange(len(p) - 1):
                getFlag = False
                if self.awareness.link_to_port.has_key((p[i], p[i+1])):
                    src_port = self.awareness.link_to_port[(p[i], p[i+1])][0]
                    if self.free_bandwidth.has_key(p[i]) and self.free_bandwidth[p[i]].has_key(src_port):
                        if self.free_bandwidth[p[i]][src_port] < (setting.MAX_CAPACITY * flow.demand):
                            break
                        else:
                            flag = True

            if flag:
                first_path = p
                self.logger.info("[GFF PATH]%s<-->%s: %s" % (flow.src, flow.dst, p))
                break
        if first_path:
            # Install new GFF_path flow entries.
            self.logger.info("[GFF INSTALLING]%s<-->%s: %s" % (flow.src, flow.dst, p))
            flow_info = (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.priority)
            self.install_flow(self.datapaths, self.awareness.link_to_port, first_path, flow_info)



    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        """
            Handle the port status changed event.
        """
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no
        dpid = msg.datapath.id
        ofproto = msg.datapath.ofproto

        reason_dict = {ofproto.OFPPR_ADD: "added",
                       ofproto.OFPPR_DELETE: "deleted",
                       ofproto.OFPPR_MODIFY: "modified", }

        # if reason in reason_dict:

        #     print "switch%d: port %s %s" % (dpid, reason_dict[reason], port_no)
        # else:
        #     print "switch%d: Illeagal port state %s %s" % (port_no, reason)

    def show_stat(self, type):
        '''
            Show statistics info according to data type.
            type: 'port' 'flow'
        '''
        if setting.TOSHOW is False:
            return

    #     bodys = self.stats[type]
    #     if(type == 'flow'):
    #         print('datapath         ''   in-port        ip-dst      '
    #               'out-port packets  bytes  flow-speed(B/s)')
    #         print('---------------- ''  -------- ----------------- '
    #               '-------- -------- -------- -----------')
    #         for dpid in bodys.keys():
    #             for stat in sorted(
    #                 [flow for flow in bodys[dpid] if flow.priority == 1],
    #                 key=lambda flow: (flow.match.get('in_port'),
    #                                   flow.match.get('ipv4_dst'))):
    #                 print('%016x %8x %17s %8x %8d %8d %8.1f' % (
    #                     dpid,
    #                     stat.match['in_port'], stat.match['ipv4_dst'],
    #                     stat.instructions[0].actions[0].port,
    #                     stat.packet_count, stat.byte_count,
    #                     abs(self.flow_speed[dpid][
    #                         (stat.match.get('in_port'),
    #                         stat.match.get('ipv4_dst'),
    #                         stat.instructions[0].actions[0].port)][-1])))
    #         print '\n'

    #     if(type == 'port'):
    #         print('datapath             port   ''rx-pkts  rx-bytes rx-error '
    #               'tx-pkts  tx-bytes tx-error  port-speed(B/s)'
    #               ' current-capacity(Kbps)  '
    #               'port-stat   link-stat')
    #         print('----------------   -------- ''-------- -------- -------- '
    #               '-------- -------- -------- '
    #               '----------------  ----------------   '
    #               '   -----------    -----------')
    #         format = '%016x %8x %8d %8d %8d %8d %8d %8d %8.1f %16d %16s %16s'
    #         for dpid in bodys.keys():
    #             for stat in sorted(bodys[dpid], key=attrgetter('port_no')):
    #                 if stat.port_no != ofproto_v1_3.OFPP_LOCAL:
    #                     print(format % (
    #                         dpid, stat.port_no,
    #                         stat.rx_packets, stat.rx_bytes, stat.rx_errors,
    #                         stat.tx_packets, stat.tx_bytes, stat.tx_errors,
    #                         abs(self.port_speed[(dpid, stat.port_no)][-1]),
    #                         self.port_features[dpid][stat.port_no][2],
    #                         self.port_features[dpid][stat.port_no][0],
    #                         self.port_features[dpid][stat.port_no][1]))
    #         print '\n'