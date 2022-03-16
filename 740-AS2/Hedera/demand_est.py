import copy


class flow:
    def __init__(self, src, dst, demand, match, priority):
        self.src = src
        self.dst = dst
        self.demand = demand
        self.converged = False
        self.receiver_limit = False
        self.match = match
        self.priority = priority

class element:
    def __init__(self):
        self.flow_num = 0
        self.demand = 0
        self.converged = False
        self.pre_demand = 0

def est_src(src, flows, M):
    converged_demand, unconverged_num = 0, 0
    for f in flows:
        if f.src == src:
            if f.converged:
                converged_demand += f.demand
            else:
                unconverged_num += 1
    if unconverged_num:
        share_rate = (1.0 -  converged_demand) / unconverged_num
        for f in flows:
            if not f.converged and f.src == src:
                M[src][f.dst].demand = share_rate
                f.demand = share_rate

def est_dst(dst, flows, M):
    total_demand, limited_demand, receiver_num = 0, 0, 0
    for f in flows:
        if f.dst == dst:
            f.receiver_limit = True
            total_demand += f.demand
            receiver_num += 1
    if total_demand <= 1.0:
        return

    if receiver_num:
        share_rate = 1.0 / receiver_num
        flag = True
        while flag:
            receiver_num = 0
            flag = False
            for f in flows:
                if f.dst == dst and f.receiver_limit:
                    if f.demand < share_rate:
                        limited_demand += f.demand
                        f.receiver_limit = False
                        flag = True
                    else:
                        receiver_num += 1
            share_rate = (1.0 - limited_demand) / receiver_num

        for f in flows:
            if f.dst == dst and f.receiver_limit:
                M[f.src][dst].demand = share_rate
                M[f.src][dst].converged = True
                f.demand = share_rate
                f.converged = True

def estimate_demand(flows, hosts):
    n = len(hosts)
    M = []
    for i in range(n):
        M.append([]) 
        for j in range(n):
            M[i].append(copy.deepcopy(element()))
    # M = [[copy.deepcopy(element())] * n for _ in range(n)]
    for f in flows:
        M[f.src][f.dst].flow_num += 1
    change_flag = True
    while change_flag:
        temp = copy.deepcopy(M)
        change_flag = False
        for src in hosts:
            est_src(src, flows, M)
        for dst in hosts:
            est_dst(dst, flows, M)
        for i in range(n):
            for j in range(n):
                # print(i, j, M[i][j].demand)
                if M[i][j].demand != M[i][j].pre_demand:
                    change_flag = True
                    M[i][j].pre_demand = M[i][j].demand

    demandsPrinting(M, hosts)

def demandsPrinting(M, hostsList):
	# """
	# 	Show the estimate results.
	# """
	# print "********************Estimated Demands********************"
	# print
	# for host in hostsList:
	# 	print host,
	# print
	# print  '_' * 140
	for row in hostsList:
		print (row,'|',)
		for col in hostsList:
			print ('%.2f' % M[row][col].demand,)
		print
	print
            
hosts = [0, 1, 2, 3 ]
flows = []
# for i in range(4):
#     for j in range(4):
#         if i == 0 and j >= 1 and j != 3:
#             flows.append(flow(i, j, 0.333, 0, 0))
#         elif i == 0 and j == 3:
#             flows.append(flow(i, j, 0.334, 0, 0))
#         elif i == 1 and j == 0:
#             flows.append(flow(i, j, 0.667, 0, 0))
#         elif i == 1 and j == 2:
#             flows.append(flow(i, j, 0.333, 0, 0))
#         elif i == 2 and j == 0:
#             flows.append(flow(i, j, 0.5, 0, 0))
#         elif i == 2 and j == 3:
#             flows.append(flow(i, j, 0.5, 0, 0))
#         elif i == 3 and j == 1:
#             flows.append(flow(i, j, 1, 0, 0))
#         else:
#             flows.append(flow(i, j, 0.0, 0, 0))
flows.append(flow(0, 1, 0.333, 0, 0))
flows.append(flow(0, 2, 0.333, 0, 0))
flows.append(flow(0, 3, 0.333, 0, 0))
flows.append(flow(1, 0, 0.667, 0, 0))
flows.append(flow(1, 2, 0.333, 0, 0))
flows.append(flow(2, 0, 0.5, 0, 0))
flows.append(flow(2, 3, 0.5, 0, 0))
flows.append(flow(3, 1, 1, 0, 0))
estimate_demand(flows, hosts)      

