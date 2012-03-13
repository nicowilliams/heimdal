
#include "baselocl.h"
#include <limits.h>

/*
 * Convert results of SPF into something nice and usable:
 * { <target> : { next_hop : <hop>,
 *                transit_path : [ <first_hop> .. <last_hop> ]
 *                distance : <distance> }
 *   ...
 * }
 */
static
int
spf_result(heim_dict_t g, heim_object_t source, heim_dict_t previous,
	   heim_dict_t distance, heim_dict_t *result)
{
    heim_dict_t dict;
    heim_object_t dist;
    heim_array_t path;
    heim_object_t node, hop;
    void *iters = NULL;
    int ret;

    dict = heim_dict_create(29);
    if (!dict)
	return ENOMEM;

    /* For every node in g */
    ret = heim_dict_iterate_nf(g, &iters, &node, NULL);
    while (ret == 0) {
	if (node == source)
	    continue; /* not including the source */
	hop = node;
	dist = heim_dict_get_value(distance, node);
	ret = heim_path_create(dict, 7, dist, NULL, node,
			       HSTR("distance"), NULL);

	/*
	 * We're going to traverse previous[] until we find the first
	 * next hop on the way to node, and we'll record the hops in
	 * path.
	 */
	if (ret) goto out;
	ret = heim_path_create(dict, 7, node, NULL, node,
			       HSTR("next_hop"), NULL);
	if (ret) goto out;
	path = heim_array_create();
	do {
	    hop = heim_dict_get_value(previous, hop);
	    if (!hop || hop == source)
		break;
	    ret = heim_array_insert_value(path, 0, hop);
	    if (ret) goto out;
	    /* FIXME: Repeating this over and over is probably expensive */
	    ret = heim_path_create(dict, 7, hop, NULL, node,
				   HSTR("next_hop"), NULL);
	    if (ret) goto out;
	} while (hop);
	ret = heim_path_create(dict, 7, path, NULL, node, HSTR("transit_path"), NULL);
	heim_release(path);
	path = NULL;
	if (ret) goto out;

	ret = heim_dict_iterate_nf(g, &iters, &node, NULL);
    }

    if (ret == -1)
	ret = 0;

out:
    if (ret)
	heim_release(dict);
    else
	*result = dict;
    return 0;
}

/**
 * Compute  Dijstra's algorithm
 *
 * @param [in] g Graph; g[node][neighbor] = distance or {"distance": distance}
 * @param [in] source Starting point in g
 * @param [in] target where you want to go (optional; NULL if not specified)
 * @param [out] paths A dict keyed by nodes in g and whose values are dicts that contain next hop, distance, and transit path
 * @param [int] filter A function to recompute the distance to a node and/or forbid a given path to a node
 * @param [int] filter_arg An opaque argument to the filter function
 *
 * The filter function receives all of the following arguments: the
 * graph, a dict keyed by nodes in the graph with values that are the
 * next hop towards the source, the source, a node in g that is being
 * considered for last hop towards the next argument (also a node in the
 * graph), and, finally, an input/output parameter for the current and
 * new distance to be considered for this hop.  The filter function
 * returns 0 on success, -1 to forbid a path, and a system error number
 * in case of error.
 *
 * @returns 0 on success, or a system error number.
 */

int
heim_shortest_path_first(heim_dict_t g, heim_object_t source,
			 heim_object_t target, heim_dict_t *paths,
			 heim_spf_filterf_t filter, void *filter_arg)
{
    heim_tid_t num_type = heim_number_get_type_id();
    heim_tid_t dict_type = heim_dict_get_type_id();
    heim_dict_t distance;  /*
			    * distance[], indexed by nodes in g;
			    * absence denotes infinite distance
			    */
    heim_dict_t previous;  /*
			    * previous[node in g] =
			    *     next hop in g towards source
			    *
			    * This is output in paths when we're done.
			    */
    heim_dict_t visited;   /*
			    * visited[node in g] =
			    *     any value when node has been visited
			    */
    heim_object_t u;       /* node in g and priority queue */
    heim_dict_t uobj;	   /* g[u] */
    heim_object_t k;       /* node in g; used in picking next u */
    heim_object_t neighbor;/* neighbor of u */
    int dist;              /* a distance */
    void *iters;           /* dict iterator */
    void *iters2;          /* dict iterator */
    int ret;

    *paths = NULL;

    neighbor = heim_dict_get_value(g, source);
    heim_assert(neighbor, "Source node must be in graph");

    distance = heim_dict_create(21);
    previous = heim_dict_create(21);
    visited = heim_dict_create(21);
    if (!distance || !previous || !visited)
	return ENOMEM;

    /*
     * distance[source node] = 0
     *
     * Initially distance[] and previous[] are empty except for
     * distance[source node] == 0; absence in distance[] denotes
     * infinite distance.
     *
     * (ret is checked below)
     */
    ret = heim_dict_set_value(distance, source, heim_number_create(0));

    /*
     * We loop over nodes u in a priority queue with all nodes from g in
     * the queue with infinite distance, except for the source node,
     * which will have 0 as its distance.  We pick a next node at the
     * bottom of the loop: the one with the smallest distance.  We also
     * remove from the queue every node we visit.
     *
     * Note that we don't use an actual priority queue abstraction.
     * Instead we use distance[] and visited[] to obtain the desired
     * effect; see below.
     */
    u = source;
    while (ret == 0 && heim_dict_get_value(visited, u) == NULL) {
	heim_object_t nobj; /* = g[u][neighbor] */
	heim_object_t ndist;/* = g[u][neighbor] or g[u][neighbor]["distance"] */
	heim_number_t disto;/* a distance object */

	/*
	 * These two breaks are the normal terminating conditions for
	 * this loop.  All other breaks are either error conditions or
	 * should not happen.
	 */
	if (u == target) break;

	/* if distance[u] == infinity break; */
	disto = heim_dict_get_value(distance, u);
	if (!disto || (heim_null_t)disto == heim_null_create()) break;

	/* Remove u from the priority queue by marking the node visited */
	ret = heim_dict_set_value(visited, u, heim_null_create());
	if (ret) break;

	/* For each neighbor of u and its distance to u */
	uobj = heim_dict_get_value(g, u);
	heim_assert(heim_get_tid(uobj) == dict_type, "g[u] must be a dict");
	iters = NULL;
	ret = heim_dict_iterate_nf(uobj, &iters, &neighbor, &nobj);
	while (ret == 0) {
	    heim_number_t num;
	    int alt, btween;

	    if (heim_get_tid(nobj) == dict_type)
		ndist = heim_dict_get_value(nobj, HSTR("distance"));
	    else if (heim_get_tid(nobj) == num_type)
		ndist = nobj;
	    else
		ndist = heim_number_create(5); /* pick a default */

	    /* ndist = g[u][neighbor]; must be a positive number */
	    heim_assert(heim_get_tid(ndist) == num_type,
			"Distance values must be numeric");
	    btween = heim_number_get_int(ndist);
	    heim_assert(btween > 0, "Distance values must be positive");

	    if (filter) {
		ret = filter(filter_arg, g, previous, source, u, neighbor,
			     nobj, &btween);
		if (ret > 0) goto out;
		if (ret < 0) continue; /* Not reachable this way */
	    }

	    /* alt = distance[u] + g[u][neighbor]; */
	    num = heim_dict_get_value(distance, u);
	    heim_assert(num, "Internal error in SPF: distance[u] not set");
	    alt = heim_number_get_int(num) + btween;

	    /* if alt < distance[neighbor] then "relax" */
	    num = heim_dict_get_value(distance, neighbor);
	    num = num ? num : heim_number_create(INT_MAX >> 8);
	    if (alt < heim_number_get_int(num)) {

		/* distance[neighbor] = distance[u] + g[u][neighbor]; (alt) */
		ret = heim_dict_set_value(distance, neighbor,
					  heim_number_create(alt));
		if (ret) goto out;

		/* previous[neighbor] = u */
		ret = heim_dict_set_value(previous, neighbor, u);
		if (ret) goto out;
	    }

	    /* Inner loop bottom: get next neighbor of node u */
	    ret = heim_dict_iterate_nf(uobj, &iters, &neighbor, &nobj);
	    if (ret > 0) goto out;
	}

	/* Outer loop bottom: pick next u from priority queue */
	dist = INT_MAX >> 8; /* largest num we can represent without boxing */
	iters2 = NULL;
	ret = heim_dict_iterate_nf(g, &iters2, &k, NULL);
	while (ret == 0) {
	    heim_object_t d;
	    heim_object_t o;

	    o = heim_dict_get_value(visited, k);
	    d = heim_dict_get_value(distance, k);
	    d = d ? d : heim_number_create(INT_MAX >> 8);

	    /* if !visited[k] && dist > distance[k] */
	    if (!o && (!d || dist > heim_number_get_int(d))) {
		dist = heim_number_get_int(d);
		u = k;
	    }

	    ret = heim_dict_iterate_nf(g, &iters2, &k, NULL);
	}
	if (ret == -1)
	    ret = 0;
	if (ret) break;
    }
    if (ret == -1)
	ret = 0;

out:
#if 0
    {
	if (!ret) {
	    heim_dict_t res = NULL;

	    spf_result(g, source, previous, distance, &res);
	    if (res)
		heim_show(res);
	    heim_release(res);
	}
    }
#endif
    if (!ret)
	ret = spf_result(g, source, previous, distance, paths);
    /*
     * distance[] could be useful to output, but can trivially be
     * recomputed from previous[], which we do output, and g
     */
    heim_release(distance);
    heim_release(visited);
    heim_release(previous);
    return ret;
}

