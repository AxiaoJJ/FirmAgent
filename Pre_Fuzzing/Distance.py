###part 2
def calculate_weight(total_edges_in_cfg, total_indirect_edges):
    if total_indirect_edges != 0: 
        w = round(total_edges_in_cfg / total_indirect_edges, 3)
    else:
        w = 1

    return min(w, 10)  

def compute_shortest_distance(rfg, node, exit_node):
    try:
        return nx.shortest_path_length(rfg, source=node, target=exit_node, weight='weight')
    except nx.NetworkXNoPath:
        return None  


def precompute_shortest_paths(rfg_reverse, pr_exit_nodes):
    shortest_paths_cache = {}
    for exit_node in pr_exit_nodes:
        if exit_node in rfg_reverse:
            print(f"Exit node {exit_node.addr} is found in the graph")
            try:
                shortest_paths_cache[exit_node] = nx.single_source_dijkstra_path_length(rfg_reverse, exit_node, weight='weight')
            except nx.NetworkXNoPath:
                print(f"No path found from exit node {exit_node.addr}")
        else:
            print(f"Exit node {exit_node.addr} is not not not not found in the graph")
    return shortest_paths_cache


def compute_node_depth_for_region(node, exit_node, shortest_paths_cache):
    if exit_node in shortest_paths_cache:
        if node in shortest_paths_cache[exit_node]:
            # print(f'{hex(node.addr)} is in shortest_paths_cache[{exit_node.addr}]')
            node_distance = shortest_paths_cache[exit_node][node]

        else:
            # print(f"Warning: node.addr {node.addr} not found in shortest_paths_cache for exit_node {exit_node.addr}")
            node_distance = -1
            # print(f'{hex(node.addr)} is nonononono in shortest_paths_cache[{exit_node.addr}]')

    else:
        # print(f"Warning: exit_node.addr {exit_node.addr} not found in shortest_paths_cache")
        node_distance = -1
        # print(f'{hex(exit_node.addr)} is nononoon in shortest_paths_cache')

    return node_distance


def process_pr_region_depth(pr_region, pr_exit_nodes, region_reach, rfg_graph):
    rfg_reverse = rfg_graph.reverse(copy=True)

    shortest_paths_cache = precompute_shortest_paths(rfg_reverse, pr_exit_nodes)

    print(f"there are {len(shortest_paths_cache)} in shortest_paths_cache")

    for exit_node, distances_from_exit_node in shortest_paths_cache.items():
        print(f'the distance of {exit_node.addr} to all nodes in pr region, number is {len(distances_from_exit_node)}')
        for target_node, distance in distances_from_exit_node.items():
            print(f'to {target_node.addr} distance is {distance}')


    PR_node_distance = {}
    PR_node_depth = {}

    pr_max_dis = -1
    for node in pr_region:
        for exit_node in pr_exit_nodes:
            if exit_node.addr in region_reach: 
                node_distance = compute_node_depth_for_region(node, exit_node, shortest_paths_cache)

                if node_distance >= 0:
                    pr_max_dis = max(pr_max_dis, node_distance)
                    if node.addr not in PR_node_depth or node_distance < PR_node_distance[node.addr][1]:
                        PR_node_distance[node.addr] = (exit_node.addr, node_distance)


    if PR_node_distance is not None:
        print(f'this pr region has {len(PR_node_distance)} node depth')
        for node_addr, (exit_node_addr, node_distance) in PR_node_distance.items():
            depth_score = pr_max_dis - node_distance
            PR_node_depth[node_addr] = (exit_node_addr, depth_score)
            print(f'{node_addr} ndoe depth score is {depth_score}')

    print(f'number of items in PR_node_depth is {len(PR_node_depth)}')
    return PR_node_depth



def calculate_node_reachability(PR_node_depth_all, region_reach, w):
    PR_node_reachability = {}

    for node_addr, (exit_node_addr, node_depth) in PR_node_depth_all.items():
        if exit_node_addr in region_reach:
            PR_node_reachability[node_addr] = node_depth + w * region_reach[exit_node_addr]
        else:
            PR_node_reachability[node_addr] = node_depth

    print(f'number in PR_node_reachability is {len(PR_node_reachability)}')
    return PR_node_reachability



def calculate_PR_node_reachability(PR_regions, pr_region_exits, region_reach, rfg_graph, indirect_edges):
    total_edges_in_cfg = rfg_graph.number_of_edges()  
    total_indirect_edges = len(indirect_edges)  
    w = calculate_weight(total_edges_in_cfg, total_indirect_edges)  
    PR_node_depth_all = {}

    for pr_region_id, pr_region in PR_regions:
        print(f'calculating region reachability of {pr_region_id} region ')
        pr_exit_nodes = pr_region_exits[pr_region_id] 
        PR_node_depth_one = process_pr_region_depth(pr_region, pr_exit_nodes, region_reach, rfg_graph)
        print(f'{pr_region_id} region node depth calculation finished')
        PR_node_depth_all.update(PR_node_depth_one)

    PR_node_reachability_all = calculate_node_reachability(PR_node_depth_all, region_reach, w)
    print(f'node reachability calculation finished')

    return PR_node_reachability_all , w, PR_node_depth_all

